#![cfg(feature = "insecure-http-for-tests")]

mod support;

use std::time::Duration;

use inshape::config::Settings;
use inshape::infisical::Client;
use inshape::{Error, Secret};
use support::{FakeInfisical, FakeProxy, Reply, base64, closed_port, route};

const LOGIN: &str = "/api/v1/auth/universal-auth/login";
const SECRETS: &str = "/api/v4/secrets";
const REVOKE: &str = "/api/v1/auth/token/revoke";
const SENTINEL: &str = "SENTINEL-9f2c";
const TOKEN: &str = "tok-SENTINEL-7d1e";
const CLIENT_SECRET: &str = "client-secret-SENTINEL-3b8a";

fn settings(api_url: &str, proxy_url: Option<&str>) -> Settings {
    Settings {
        client_id: "cid".to_owned(),
        client_secret: Secret::new(CLIENT_SECRET.to_owned()),
        project_id: "proj 1&x=y".to_owned(),
        env: "prod".to_owned(),
        paths: vec!["/".to_owned()],
        api_url: api_url.to_owned(),
        proxy_url: proxy_url.map(|p| Secret::new(p.to_owned())),
    }
}

fn client(server: &FakeInfisical) -> Client {
    Client::new(&settings(&server.url(), None)).expect("client")
}

fn token() -> Secret {
    Secret::new(TOKEN.to_owned())
}

fn login_ok() -> Reply {
    Reply::json(
        200,
        &format!(r#"{{"accessToken":"{TOKEN}","expiresIn":7200,"tokenType":"Bearer"}}"#),
    )
}

fn assert_clean(err: &Error) {
    let text = err.to_string();
    for secret in [SENTINEL, TOKEN, CLIENT_SECRET, "pa55"] {
        assert!(!text.contains(secret), "{secret} leaked in {text:?}");
    }
}

#[test]
fn login_posts_client_credentials() {
    let server = FakeInfisical::start(vec![route("POST", LOGIN, login_ok())]);
    let got = client(&server).login().expect("login");
    assert_eq!(got.expose(), TOKEN);

    let reqs = server.requests();
    assert_eq!(reqs.len(), 1);
    let req = &reqs[0];
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, LOGIN);
    assert_eq!(
        req.body_json(),
        serde_json::json!({"clientId": "cid", "clientSecret": CLIENT_SECRET})
    );
    assert!(
        req.header("content-type")
            .is_some_and(|v| v.starts_with("application/json"))
    );
    assert_eq!(
        req.header("user-agent"),
        Some(format!("inshape/{}", inshape::VERSION).as_str())
    );
    assert_eq!(req.header("authorization"), None);
}

#[test]
fn login_without_access_token_is_refused() {
    let server = FakeInfisical::start(vec![route("POST", LOGIN, Reply::json(200, "{}"))]);
    let err = client(&server).login().unwrap_err();
    assert!(matches!(err, Error::Refused(_)), "{err:?}");
    assert!(err.to_string().contains("sign-in"), "{err}");
}

#[test]
fn fetch_sends_exact_query() {
    let body = r#"{"secrets":[
        {"secretKey":"A","secretValue":"1","environment":"prod","secretPath":"/core","secretValueHidden":false},
        {"secretKey":"B","secretValue":"2"}
    ],"imports":[]}"#;
    let server = FakeInfisical::start(vec![route("GET", SECRETS, Reply::json(200, body))]);
    let secrets = client(&server).fetch(&token(), "/core").expect("fetch");

    let reqs = server.requests();
    assert_eq!(reqs.len(), 1);
    let req = &reqs[0];
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, SECRETS);
    let pairs = req.query_pairs();
    let expected: Vec<(String, String)> = [
        ("projectId", "proj 1&x=y"),
        ("environment", "prod"),
        ("secretPath", "/core"),
        ("expandSecretReferences", "false"),
        ("includeImports", "false"),
        ("recursive", "false"),
        ("viewSecretValue", "true"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    assert_eq!(pairs, expected);
    assert!(!req.query.contains(' '), "{}", req.query);
    assert_eq!(
        req.header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );

    assert_eq!(secrets.len(), 2);
    assert_eq!(secrets[0].key, "A");
    assert_eq!(secrets[0].value.expose(), "1");
    assert_eq!(secrets[0].environment.as_deref(), Some("prod"));
    assert_eq!(secrets[0].secret_path.as_deref(), Some("/core"));
    assert!(!secrets[0].value_hidden);
    assert_eq!(secrets[1].key, "B");
    assert_eq!(secrets[1].environment, None);
    assert_eq!(secrets[1].secret_path, None);
    assert!(!secrets[1].value_hidden);
}

#[test]
fn fetch_reads_value_hidden() {
    let body = r#"{"secrets":[{"secretKey":"A","secretValue":"<hidden-by-infisical>","secretValueHidden":true}]}"#;
    let server = FakeInfisical::start(vec![route("GET", SECRETS, Reply::json(200, body))]);
    let secrets = client(&server).fetch(&token(), "/").expect("fetch");
    assert!(secrets[0].value_hidden);
}

#[test]
fn fetch_missing_key_or_value_is_refused() {
    for body in [
        r#"{"secrets":[{"secretValue":"SENTINEL-9f2c"}]}"#,
        r#"{"secrets":[{"secretKey":"A"}]}"#,
        r#"{"other":[]}"#,
    ] {
        let server = FakeInfisical::start(vec![route("GET", SECRETS, Reply::json(200, body))]);
        let err = client(&server).fetch(&token(), "/core").unwrap_err();
        assert!(matches!(err, Error::Refused(_)), "{body}: {err:?}");
        assert!(err.to_string().contains("/core"), "{err}");
        assert_clean(&err);
    }
}

#[test]
fn revoke_posts_token() {
    let server = FakeInfisical::start(vec![route(
        "POST",
        REVOKE,
        Reply::json(200, r#"{"message":"ok"}"#),
    )]);
    client(&server).revoke(&token()).expect("revoke");
    let reqs = server.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, REVOKE);
    assert_eq!(
        reqs[0].body_json(),
        serde_json::json!({"accessToken": TOKEN})
    );
}

#[test]
fn revoke_failure_is_an_error() {
    let server = FakeInfisical::start(vec![route("POST", REVOKE, Reply::json(500, "{}"))]);
    let err = client(&server).revoke(&token()).unwrap_err();
    assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
    assert!(err.to_string().contains("revoking the token"), "{err}");
    assert_eq!(inshape::infisical::http_status(&err), Some(500));
}

#[test]
fn status_401_and_403_are_auth() {
    for status in [401, 403] {
        let server = FakeInfisical::start(vec![
            route("POST", LOGIN, Reply::json(status, "{}")),
            route("GET", SECRETS, Reply::json(status, "{}")),
        ]);
        let c = client(&server);
        let err = c.login().unwrap_err();
        assert!(matches!(err, Error::Auth(_)), "{err:?}");
        assert!(err.to_string().contains(&status.to_string()), "{err}");
        let err = c.fetch(&token(), "/").unwrap_err();
        assert!(matches!(err, Error::Auth(_)), "{err:?}");
        assert_clean(&err);
    }
}

#[test]
fn status_500_is_unavailable() {
    for status in [500, 502, 503] {
        let server = FakeInfisical::start(vec![route("POST", LOGIN, Reply::json(status, "{}"))]);
        let err = client(&server).login().unwrap_err();
        assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
        assert!(err.to_string().contains(&status.to_string()), "{err}");
    }
}

#[test]
fn status_404_is_refused() {
    for status in [400, 404, 422, 302, 204] {
        let server = FakeInfisical::start(vec![route("GET", SECRETS, Reply::json(status, ""))]);
        let err = client(&server).fetch(&token(), "/").unwrap_err();
        assert!(matches!(err, Error::Refused(_)), "{status}: {err:?}");
    }
}

#[test]
#[ignore = "takes 11 s; CI runs it with --include-ignored"]
fn timeout_is_unavailable() {
    let server = FakeInfisical::start(vec![route(
        "POST",
        LOGIN,
        login_ok().delayed(Duration::from_secs(11)),
    )]);
    let err = client(&server).login().unwrap_err();
    assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
    assert!(err.to_string().contains("timed out"), "{err}");
    assert_clean(&err);
}

#[test]
fn connection_refused_is_unavailable() {
    let url = format!("http://127.0.0.1:{}", closed_port());
    let err = Client::new(&settings(&url, None))
        .expect("client")
        .login()
        .unwrap_err();
    assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
    assert!(!err.to_string().contains("127.0.0.1"), "{err}");
}

#[test]
fn tls_failure_is_unavailable() {
    let server = support::PlainHttpListener::start();
    let url = format!("https://{}", server.addr());
    let err = Client::new(&settings(&url, None))
        .expect("client")
        .login()
        .unwrap_err();
    assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
    assert!(err.to_string().contains("TLS"), "{err}");
}

#[test]
fn bad_json_is_refused() {
    for body in ["not json", r#"{"secrets":"SENTINEL-9f2c"}"#] {
        let server = FakeInfisical::start(vec![route("GET", SECRETS, Reply::json(200, body))]);
        let err = client(&server).fetch(&token(), "/").unwrap_err();
        assert!(matches!(err, Error::Refused(_)), "{err:?}");
        assert_clean(&err);
    }
}

#[test]
fn body_over_1_mib_is_refused() {
    let pad = "a".repeat(1024 * 1024);
    let body = format!(r#"{{"secrets":[],"pad":"{pad}"}}"#);
    let server = FakeInfisical::start(vec![route(
        "GET",
        SECRETS,
        Reply::bytes(200, body.into_bytes()),
    )]);
    let err = client(&server).fetch(&token(), "/").unwrap_err();
    assert!(matches!(err, Error::Refused(_)), "{err:?}");
    assert!(err.to_string().contains("1 MiB"), "{err}");
}

#[test]
fn body_just_under_1_mib_is_read() {
    let mut body = String::from(r#"{"secrets":[],"pad":""#);
    let fill = 1024 * 1024 - body.len() - 2;
    body.push_str(&"a".repeat(fill));
    body.push_str("\"}");
    assert_eq!(body.len(), 1024 * 1024);
    let server = FakeInfisical::start(vec![route(
        "GET",
        SECRETS,
        Reply::bytes(200, body.into_bytes()),
    )]);
    assert!(
        client(&server)
            .fetch(&token(), "/")
            .expect("fetch")
            .is_empty()
    );
}

#[test]
fn proxy_used_with_auth() {
    let server = FakeInfisical::start(vec![route("POST", LOGIN, login_ok())]);
    let proxy = FakeProxy::start(Some("u:pa55"));
    let proxy_url = format!("http://u:pa55@{}", proxy.addr());
    let c = Client::new(&settings(&server.url(), Some(&proxy_url))).expect("client");
    assert_eq!(c.login().expect("login").expose(), TOKEN);
    assert!(proxy.auth_seen());
    assert_eq!(proxy.targets(), vec![server.addr()]);
    assert_eq!(server.requests().len(), 1);
    assert_eq!(server.requests()[0].header("proxy-authorization"), None);
}

#[test]
fn proxy_without_credentials_sends_no_auth() {
    let server = FakeInfisical::start(vec![route("POST", LOGIN, login_ok())]);
    let proxy = FakeProxy::start(None);
    let proxy_url = format!("http://{}", proxy.addr());
    let c = Client::new(&settings(&server.url(), Some(&proxy_url))).expect("client");
    c.login().expect("login");
    assert!(!proxy.auth_seen());
    assert_eq!(proxy.targets(), vec![server.addr()]);
}

#[test]
fn proxy_407_is_unavailable_and_hides_credentials() {
    let server = FakeInfisical::start(vec![route("POST", LOGIN, login_ok())]);
    let proxy = FakeProxy::start(Some("u:right"));
    let proxy_url = format!("http://user9:pa55@{}", proxy.addr());
    let c = Client::new(&settings(&server.url(), Some(&proxy_url))).expect("client");
    let err = c.login().unwrap_err();
    assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
    let text = err.to_string();
    assert!(text.contains("proxy"), "{text}");
    assert!(proxy.auth_seen());
    assert!(proxy.targets().is_empty());
    assert!(server.requests().is_empty());
    for hidden in ["pa55", "user9", &proxy.addr(), &base64(b"user9:pa55")] {
        assert!(!text.contains(hidden), "{hidden} leaked in {text:?}");
    }
}

#[test]
fn proxy_down_is_unavailable() {
    let server = FakeInfisical::start(vec![route("POST", LOGIN, login_ok())]);
    let proxy_url = format!("http://u:pa55@127.0.0.1:{}", closed_port());
    let c = Client::new(&settings(&server.url(), Some(&proxy_url))).expect("client");
    let err = c.login().unwrap_err();
    assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
    assert!(server.requests().is_empty());
    assert_clean(&err);
    assert!(!err.to_string().contains("127.0.0.1"), "{err}");
}

#[test]
fn redirects_are_refused_and_not_followed() {
    let elsewhere = FakeInfisical::start(vec![
        route("POST", LOGIN, login_ok()),
        route("GET", SECRETS, Reply::json(200, r#"{"secrets":[]}"#)),
    ]);
    let login_to = format!("{}{LOGIN}", elsewhere.url());
    let fetch_to = format!("{}{SECRETS}", elsewhere.url());
    let server = FakeInfisical::start(vec![
        route(
            "POST",
            LOGIN,
            Reply::json(302, "").with_header("Location", &login_to),
        ),
        route(
            "GET",
            SECRETS,
            Reply::json(302, "").with_header("Location", &fetch_to),
        ),
    ]);
    let c = client(&server);
    let err = c.login().unwrap_err();
    assert!(matches!(err, Error::Refused(_)), "{err:?}");
    assert!(err.to_string().contains("302"), "{err}");
    let err = c.fetch(&token(), "/").unwrap_err();
    assert!(matches!(err, Error::Refused(_)), "{err:?}");
    assert_clean(&err);
    assert_eq!(server.requests().len(), 2);
    assert!(elsewhere.requests().is_empty());
}

#[test]
fn error_text_never_contains_body() {
    let body = format!(r#"{{"message":"{SENTINEL}","error":"{SENTINEL}"}}"#);
    for status in [500, 404, 401] {
        let server = FakeInfisical::start(vec![
            route("POST", LOGIN, Reply::json(status, &body)),
            route("GET", SECRETS, Reply::json(status, &body)),
            route("POST", REVOKE, Reply::json(status, &body)),
        ]);
        let c = client(&server);
        assert_clean(&c.login().unwrap_err());
        assert_clean(&c.fetch(&token(), "/").unwrap_err());
        assert_clean(&c.revoke(&token()).unwrap_err());
    }
}

#[test]
fn client_debug_hides_secrets() {
    let proxy_url = "http://u:pa55@127.0.0.1:1";
    let c = Client::new(&settings("http://127.0.0.1:1", Some(proxy_url))).expect("client");
    let shown = format!("{c:?}");
    assert!(!shown.contains("pa55"), "{shown}");
    assert!(!shown.contains(CLIENT_SECRET), "{shown}");
}

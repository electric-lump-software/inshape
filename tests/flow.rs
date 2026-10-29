#![cfg(feature = "insecure-http-for-tests")]

mod support;

use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use support::{FakeInfisical, FakeProxy, Reply, Route, closed_port, route};

const BIN: &str = env!("CARGO_BIN_EXE_inshape");
const LOGIN: &str = "/api/v1/auth/universal-auth/login";
const SECRETS: &str = "/api/v4/secrets";
const REVOKE: &str = "/api/v1/auth/token/revoke";

const SENTINEL: &str = "SENTINEL-9f2c";
const TOKEN: &str = "tok-SENTINEL-9f2c";
const CLIENT_SECRET: &str = "client-secret-SENTINEL-9f2c";
const PROXY_CREDS: &str = "user:pw-SENTINEL-9f2c";
const SECRET_X: &str = "x-SENTINEL-9f2c";
const STRIPE_KEY: &str = "sk-SENTINEL-9f2c";
const CANARY_VALUE: &str = "canary-SENTINEL-9f2c";
const CHILD: &str = "/usr/bin/env";
const HOST_PATH: &str = "/usr/bin:/bin";

struct Allowlist(PathBuf);

impl Allowlist {
    fn new(text: &str) -> Allowlist {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("inshape-flow-{}-{n}.allowlist", std::process::id()));
        std::fs::write(&path, text).expect("write allowlist");
        Allowlist(path)
    }

    fn standard() -> Allowlist {
        Allowlist::new("SECRET_X\nSTRIPE_KEY\n")
    }
}

impl Drop for Allowlist {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn folder_body(path: &str, secrets: &[(&str, &str)]) -> String {
    let items: Vec<serde_json::Value> = secrets
        .iter()
        .map(|(key, value)| {
            serde_json::json!({
                "secretKey": key,
                "secretValue": value,
                "environment": "prod",
                "secretPath": path,
                "secretValueHidden": false,
            })
        })
        .collect();
    serde_json::json!({ "secrets": items, "imports": [] }).to_string()
}

fn login_ok() -> Reply {
    Reply::json(
        200,
        &format!(r#"{{"accessToken":"{TOKEN}","expiresIn":7200,"tokenType":"Bearer"}}"#),
    )
}

fn core_ok() -> Reply {
    Reply::json(
        200,
        &folder_body(
            "/core",
            &[
                ("SECRET_X", SECRET_X),
                ("INFISICAL_CANARY_CORE", CANARY_VALUE),
            ],
        ),
    )
}

fn shared_ok() -> Reply {
    Reply::json(
        200,
        &folder_body(
            "/shared",
            &[
                ("INFISICAL_CANARY_SHARED", CANARY_VALUE),
                ("STRIPE_KEY", STRIPE_KEY),
            ],
        ),
    )
}

fn revoke_ok() -> Reply {
    Reply::json(200, r#"{"message":"ok"}"#)
}

fn routes(login: Reply, core: Reply, shared: Reply, revoke: Reply) -> Vec<Route> {
    vec![
        route("POST", LOGIN, login),
        route("GET", SECRETS, core).when_query("secretPath", "/core"),
        route("GET", SECRETS, shared).when_query("secretPath", "/shared"),
        route("POST", REVOKE, revoke),
    ]
}

fn ok_server() -> FakeInfisical {
    FakeInfisical::start(routes(login_ok(), core_ok(), shared_ok(), revoke_ok()))
}

fn pairs(list: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    list.iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect()
}

fn configured(api_url: &str) -> Vec<(OsString, OsString)> {
    pairs(&[
        ("PATH", HOST_PATH),
        ("KEEP_ME", "kept"),
        ("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "cid"),
        ("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", CLIENT_SECRET),
        ("INFISICAL_PROJECT_ID", "proj"),
        ("INFISICAL_ENV", "prod"),
        ("INFISICAL_PATHS", "/core /shared"),
        ("INFISICAL_API_URL", api_url),
    ])
}

fn with(mut env: Vec<(OsString, OsString)>, extra: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    env.extend(pairs(extra));
    env
}

fn command(
    env: &[(OsString, OsString)],
    allow: &Allowlist,
    flags: &[&str],
    cmd: &[&str],
) -> Command {
    let mut c = Command::new(BIN);
    c.env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .args(flags)
        .arg("--allowlist")
        .arg(&allow.0)
        .arg("--")
        .args(cmd);
    c
}

fn run(env: &[(OsString, OsString)], allow: &Allowlist) -> Output {
    command(env, allow, &[], &[CHILD])
        .output()
        .expect("run inshape")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn child_env(out: &Output) -> Vec<String> {
    let mut lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    lines.sort();
    lines
}

fn sorted(list: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = list.iter().map(|s| (*s).to_owned()).collect();
    v.sort();
    v
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("exit code")
}

fn revoked(server: &FakeInfisical) -> bool {
    server
        .requests()
        .iter()
        .any(|r| r.method == "POST" && r.path == REVOKE)
}

#[test]
fn exec_gets_exact_environment() {
    let server = ok_server();
    let allow = Allowlist::standard();
    let out = run(&configured(&server.url()), &allow);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(
        child_env(&out),
        sorted(&[
            &format!("PATH={HOST_PATH}"),
            "KEEP_ME=kept",
            &format!("SECRET_X={SECRET_X}"),
            &format!("STRIPE_KEY={STRIPE_KEY}"),
            &format!("INFISICAL_CANARY_CORE={CANARY_VALUE}"),
            &format!("INFISICAL_CANARY_SHARED={CANARY_VALUE}"),
        ])
    );
    assert_eq!(
        stderr(&out),
        "inshape: loaded 4 secrets from /core (2), /shared (2); \
         canaries: INFISICAL_CANARY_CORE INFISICAL_CANARY_SHARED\n"
    );
    assert!(revoked(&server));
}

#[test]
fn non_utf8_host_var_passes_through() {
    use std::os::unix::ffi::OsStringExt;
    let server = ok_server();
    let allow = Allowlist::standard();
    let mut env = configured(&server.url());
    env.push((OsString::from("ODD"), OsString::from_vec(vec![0xff, 0xfe])));
    let out = run(&env, &allow);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        out.stdout
            .split(|b| *b == b'\n')
            .any(|line| line == b"ODD=\xff\xfe"),
        "{:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn host_name_differing_in_case_is_not_a_clash() {
    let server = ok_server();
    let allow = Allowlist::standard();
    let out = run(
        &with(configured(&server.url()), &[("secret_x", "lower")]),
        &allow,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let env = child_env(&out);
    assert!(env.contains(&"secret_x=lower".to_owned()), "{env:?}");
    assert!(env.contains(&format!("SECRET_X={SECRET_X}")), "{env:?}");
}

#[test]
fn optional_and_unconfigured_execs_unchanged() {
    let allow = Allowlist::standard();
    let env = pairs(&[
        ("PATH", HOST_PATH),
        ("KEEP_ME", "kept"),
        ("INFISICAL_PATHS", "/core"),
    ]);
    let out = command(&env, &allow, &["--optional"], &[CHILD])
        .output()
        .expect("run inshape");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(
        child_env(&out),
        sorted(&[&format!("PATH={HOST_PATH}"), "KEEP_ME=kept"])
    );
    assert_eq!(
        stderr(&out),
        "inshape: Infisical not configured; starting without it\n"
    );
}

#[test]
fn optional_and_unconfigured_strips_own_settings() {
    let allow = Allowlist::standard();
    let env = pairs(&[
        ("PATH", HOST_PATH),
        ("INFISICAL_PROXY_URL", "http://u:SENTINEL-9f2c@127.0.0.1:1"),
        ("INFISICAL_API_URL", "http://127.0.0.1:1"),
    ]);
    let out = command(&env, &allow, &["--optional"], &[CHILD])
        .output()
        .expect("run inshape");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(child_env(&out), sorted(&[&format!("PATH={HOST_PATH}")]));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("9f2c"));
}

#[test]
fn host_clash_fails_before_any_network_call() {
    let server = ok_server();
    let allow = Allowlist::standard();
    let mut env = with(configured(&server.url()), &[("SECRET_X", "leftover")]);
    let out = run(&env, &allow);
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    assert!(server.requests().is_empty(), "{:?}", server.requests());

    let dead = format!("http://127.0.0.1:{}", closed_port());
    env = with(configured(&dead), &[("INFISICAL_CANARY_OLD", "stale")]);
    let out = run(&env, &allow);
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("INFISICAL_CANARY_OLD"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn unconfigured_without_optional_exits_64() {
    let allow = Allowlist::standard();
    let out = run(&pairs(&[("PATH", HOST_PATH)]), &allow);
    assert_eq!(code(&out), 64);
    assert!(out.stdout.is_empty());
    let err = stderr(&out);
    assert!(err.starts_with("inshape: "), "{err}");
    assert!(err.contains("not configured"), "{err}");
    assert!(err.contains("--optional"), "{err}");
}

#[test]
fn partial_config_exits_64() {
    let allow = Allowlist::standard();
    let out = run(
        &pairs(&[
            ("PATH", HOST_PATH),
            ("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "cid"),
        ]),
        &allow,
    );
    assert_eq!(code(&out), 64);
    let err = stderr(&out);
    assert!(err.contains("INFISICAL_PROJECT_ID"), "{err}");
    let out = command(
        &pairs(&[("PATH", HOST_PATH), ("INFISICAL_ENV", "prod")]),
        &allow,
        &["--optional"],
        &[CHILD],
    )
    .output()
    .expect("run inshape");
    assert_eq!(code(&out), 64, "--optional must not hide a partial config");
}

#[test]
fn bad_allowlist_exits_64() {
    let allow = Allowlist::new("PATH\n");
    let out = run(&configured("http://127.0.0.1:9"), &allow);
    assert_eq!(code(&out), 64);
    assert!(stderr(&out).contains("denied name"), "{}", stderr(&out));
}

#[test]
fn host_sets_allowlisted_name_exits_64_and_names_it() {
    let server = ok_server();
    let allow = Allowlist::standard();
    let host_value = "leftover-SENTINEL-9f2c";
    let out = run(
        &with(configured(&server.url()), &[("SECRET_X", host_value)]),
        &allow,
    );
    assert_eq!(code(&out), 64);
    assert!(out.stdout.is_empty());
    let err = stderr(&out);
    assert!(err.contains("SECRET_X"), "{err}");
    assert!(!err.contains("leftover"), "{err}");
    assert!(!err.contains(SENTINEL), "{err}");
}

#[test]
fn host_sets_allowlisted_name_not_fetched_exits_64() {
    let server = ok_server();
    let allow = Allowlist::new("SECRET_X\nSTRIPE_KEY\nUNUSED_NAME\n");
    let out = run(
        &with(configured(&server.url()), &[("UNUSED_NAME", "v")]),
        &allow,
    );
    assert_eq!(code(&out), 64);
    assert!(stderr(&out).contains("UNUSED_NAME"), "{}", stderr(&out));
}

#[test]
fn host_sets_canary_exits_64() {
    let server = ok_server();
    let allow = Allowlist::standard();
    let out = run(
        &with(
            configured(&server.url()),
            &[("INFISICAL_CANARY_OLD", "stale")],
        ),
        &allow,
    );
    assert_eq!(code(&out), 64);
    assert!(out.stdout.is_empty());
    let err = stderr(&out);
    assert!(err.contains("INFISICAL_CANARY_OLD"), "{err}");
    assert!(!err.contains("stale"), "{err}");
}

#[test]
fn ambient_proxy_vars_ignored() {
    let server = ok_server();
    let allow = Allowlist::standard();
    let dead = format!("http://127.0.0.1:{}", closed_port());
    let out = run(
        &with(
            configured(&server.url()),
            &[
                ("HTTP_PROXY", &dead),
                ("HTTPS_PROXY", &dead),
                ("http_proxy", &dead),
                ("https_proxy", &dead),
                ("ALL_PROXY", &dead),
                ("NO_PROXY", "*"),
                ("no_proxy", "*"),
            ],
        ),
        &allow,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let env = child_env(&out);
    assert!(env.contains(&format!("SECRET_X={SECRET_X}")), "{env:?}");
    assert!(env.contains(&format!("HTTPS_PROXY={dead}")), "{env:?}");
}

#[test]
fn configured_proxy_is_used() {
    let server = ok_server();
    let proxy = FakeProxy::start(Some(PROXY_CREDS));
    let allow = Allowlist::standard();
    let proxy_url = format!("http://{PROXY_CREDS}@{}", proxy.addr());
    let out = run(
        &with(
            configured(&server.url()),
            &[("INFISICAL_PROXY_URL", &proxy_url)],
        ),
        &allow,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(proxy.auth_seen());
    assert!(proxy.targets().contains(&server.addr()));
    let env = child_env(&out);
    assert!(
        !env.iter().any(|l| l.starts_with("INFISICAL_PROXY_URL=")),
        "{env:?}"
    );
}

#[test]
fn refused_secret_exits_65() {
    let core = Reply::json(
        200,
        &folder_body(
            "/core",
            &[
                ("SECRET_Z", SECRET_X),
                ("INFISICAL_CANARY_CORE", CANARY_VALUE),
            ],
        ),
    );
    let server = FakeInfisical::start(routes(login_ok(), core, shared_ok(), revoke_ok()));
    let allow = Allowlist::standard();
    let out = run(&configured(&server.url()), &allow);
    assert_eq!(code(&out), 65);
    assert!(out.stdout.is_empty());
    let err = stderr(&out);
    assert!(
        err.contains("/core: SECRET_Z is not in the allowlist"),
        "{err}"
    );
    assert!(
        revoked(&server),
        "the token is revoked even when checks fail"
    );
}

#[test]
fn auth_failure_exits_77() {
    let server = FakeInfisical::start(routes(
        Reply::json(401, "{}"),
        core_ok(),
        shared_ok(),
        revoke_ok(),
    ));
    let allow = Allowlist::standard();
    let out = run(&configured(&server.url()), &allow);
    assert_eq!(code(&out), 77);
    assert!(stderr(&out).contains("sign-in"), "{}", stderr(&out));
    assert!(!revoked(&server), "no token, nothing to revoke");

    let server = FakeInfisical::start(routes(
        login_ok(),
        core_ok(),
        Reply::json(403, "{}"),
        revoke_ok(),
    ));
    let out = run(&configured(&server.url()), &allow);
    assert_eq!(code(&out), 77);
    assert!(stderr(&out).contains("/shared"), "{}", stderr(&out));
    assert!(revoked(&server), "a fetch failure still revokes the token");
}

#[test]
fn unreachable_exits_69() {
    let allow = Allowlist::standard();
    let out = run(
        &configured(&format!("http://127.0.0.1:{}", closed_port())),
        &allow,
    );
    assert_eq!(code(&out), 69);
    assert!(out.stdout.is_empty());

    let server = FakeInfisical::start(routes(
        login_ok(),
        Reply::json(503, "{}"),
        shared_ok(),
        revoke_ok(),
    ));
    let out = run(&configured(&server.url()), &allow);
    assert_eq!(code(&out), 69);
    assert!(revoked(&server));
}

#[test]
fn exec_missing_command_exits_71() {
    let allow = Allowlist::standard();
    for cmd in ["/nonexistent/inshape-cmd", "inshape-no-such-command"] {
        let server = ok_server();
        let out = command(
            &configured(&server.url()),
            &allow,
            &[],
            &[cmd, "--flag=arg-SENTINEL-9f2c"],
        )
        .output()
        .expect("run inshape");
        assert_eq!(code(&out), 71, "{cmd}");
        let err = stderr(&out);
        assert!(err.contains(cmd), "{err}");
        assert!(!err.contains("--flag"), "{err}");
        assert!(revoked(&server));
    }
}

#[test]
fn command_found_on_path() {
    let server = ok_server();
    let allow = Allowlist::standard();
    let out = command(&configured(&server.url()), &allow, &[], &["env"])
        .output()
        .expect("run inshape");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(child_env(&out).contains(&format!("SECRET_X={SECRET_X}")));
}

#[test]
fn revoke_failure_warns_and_continues() {
    let server = FakeInfisical::start(routes(
        login_ok(),
        core_ok(),
        shared_ok(),
        Reply::json(500, "{}"),
    ));
    let allow = Allowlist::standard();
    let out = run(&configured(&server.url()), &allow);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains(
            "inshape: could not revoke the sign-in token (status 500); it will expire on its own\n"
        ),
        "{err}"
    );
    assert!(err.contains("inshape: loaded 4 secrets"), "{err}");
    assert!(child_env(&out).contains(&format!("SECRET_X={SECRET_X}")));
}

#[test]
fn revoke_called_before_exec() {
    let server = ok_server();
    let allow = Allowlist::standard();
    let mut child = command(&configured(&server.url()), &allow, &[], &[CHILD])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn inshape");
    let mut stdout = child.stdout.take().expect("stdout");
    let mut first = [0u8; 1];
    stdout.read_exact(&mut first).expect("child printed");
    assert!(
        revoked(&server),
        "the revoke must reach Infisical before the command starts"
    );
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).expect("read rest");
    assert!(child.wait().expect("wait").success());
}

type Scenario<'a> = (
    &'a str,
    Vec<Route>,
    Option<&'a FakeProxy>,
    Vec<(&'a str, &'a str)>,
    i32,
);

fn assert_no_sentinel(label: &str, out: &Output) {
    let err = stderr(out);
    assert!(!err.contains(SENTINEL), "{label}: {err}");
    assert!(!err.contains("9f2c"), "{label}: {err}");
    assert!(err.starts_with("inshape: "), "{label}: {err}");
}

#[test]
fn sentinel_never_in_stderr() {
    let proxy = FakeProxy::start(Some(PROXY_CREDS));
    let bad_proxy = FakeProxy::start(Some("other:creds"));
    let via = |proxy: &FakeProxy, env: Vec<(OsString, OsString)>| {
        let url = format!("http://{PROXY_CREDS}@{}", proxy.addr());
        with(env, &[("INFISICAL_PROXY_URL", &url)])
    };
    let allow = Allowlist::standard();
    let sentinel_body = format!(r#"{{"message":"{SENTINEL}","secrets":"{SENTINEL}"}}"#);
    let refused_core = Reply::json(
        200,
        &folder_body(
            "/core",
            &[
                ("SECRET_Z", SECRET_X),
                ("SECRET_X", " "),
                ("bad-SENTINEL-9f2c", SECRET_X),
                ("INFISICAL_CANARY_CORE", CANARY_VALUE),
            ],
        ),
    );
    let mut wrong_env: serde_json::Value = serde_json::from_str(&folder_body(
        "/shared",
        &[
            ("INFISICAL_CANARY_SHARED", CANARY_VALUE),
            ("STRIPE_KEY", STRIPE_KEY),
        ],
    ))
    .unwrap();
    wrong_env["secrets"][1]["environment"] = serde_json::json!(SENTINEL);
    wrong_env["secrets"][1]["secretPath"] = serde_json::json!(SENTINEL);

    let scenarios: Vec<Scenario> = vec![
        (
            "success",
            routes(login_ok(), core_ok(), shared_ok(), revoke_ok()),
            Some(&proxy),
            vec![],
            0,
        ),
        (
            "host clash",
            routes(login_ok(), core_ok(), shared_ok(), revoke_ok()),
            Some(&proxy),
            vec![("STRIPE_KEY", SECRET_X)],
            64,
        ),
        (
            "host canary",
            routes(login_ok(), core_ok(), shared_ok(), revoke_ok()),
            Some(&proxy),
            vec![("INFISICAL_CANARY_X", SECRET_X)],
            64,
        ),
        (
            "refused",
            routes(login_ok(), refused_core, shared_ok(), revoke_ok()),
            Some(&proxy),
            vec![],
            65,
        ),
        (
            "wrong env",
            routes(
                login_ok(),
                core_ok(),
                Reply::json(200, &wrong_env.to_string()),
                revoke_ok(),
            ),
            Some(&proxy),
            vec![],
            65,
        ),
        (
            "login 401",
            routes(
                Reply::json(401, &sentinel_body),
                core_ok(),
                shared_ok(),
                revoke_ok(),
            ),
            Some(&proxy),
            vec![],
            77,
        ),
        (
            "fetch 403",
            routes(
                login_ok(),
                Reply::json(403, &sentinel_body),
                shared_ok(),
                revoke_ok(),
            ),
            Some(&proxy),
            vec![],
            77,
        ),
        (
            "fetch 500",
            routes(
                login_ok(),
                core_ok(),
                Reply::json(500, &sentinel_body),
                revoke_ok(),
            ),
            Some(&proxy),
            vec![],
            69,
        ),
        (
            "fetch 404",
            routes(
                login_ok(),
                Reply::json(404, &sentinel_body),
                shared_ok(),
                revoke_ok(),
            ),
            Some(&proxy),
            vec![],
            65,
        ),
        (
            "fetch bad json",
            routes(
                login_ok(),
                Reply::json(200, &sentinel_body),
                shared_ok(),
                revoke_ok(),
            ),
            Some(&proxy),
            vec![],
            65,
        ),
        (
            "login bad json",
            routes(
                Reply::json(200, &sentinel_body),
                core_ok(),
                shared_ok(),
                revoke_ok(),
            ),
            Some(&proxy),
            vec![],
            65,
        ),
        (
            "revoke 500",
            routes(
                login_ok(),
                core_ok(),
                shared_ok(),
                Reply::json(500, &sentinel_body),
            ),
            Some(&proxy),
            vec![],
            0,
        ),
        (
            "revoke 401 then refused",
            routes(
                login_ok(),
                Reply::json(400, &sentinel_body),
                shared_ok(),
                Reply::json(401, &sentinel_body),
            ),
            Some(&proxy),
            vec![],
            65,
        ),
        (
            "proxy rejects creds",
            routes(login_ok(), core_ok(), shared_ok(), revoke_ok()),
            Some(&bad_proxy),
            vec![],
            69,
        ),
        (
            "partial config",
            vec![],
            None,
            vec![("INFISICAL_PROJECT_ID", "")],
            64,
        ),
    ];

    for (label, routes, proxy, extra, expected) in scenarios {
        let server = FakeInfisical::start(routes);
        let mut env = configured(&server.url());
        if let Some(proxy) = proxy {
            env = via(proxy, env);
        }
        let env = with(env, &extra);
        let out = run(&env, &allow);
        assert_eq!(code(&out), expected, "{label}: {}", stderr(&out));
        assert_no_sentinel(label, &out);
        if expected != 0 {
            assert!(out.stdout.is_empty(), "{label}");
        }
    }

    let dead_proxy = format!("http://{PROXY_CREDS}@127.0.0.1:{}", closed_port());
    let out = run(
        &with(
            configured("http://127.0.0.1:9"),
            &[("INFISICAL_PROXY_URL", &dead_proxy)],
        ),
        &allow,
    );
    assert_eq!(code(&out), 69);
    assert_no_sentinel("proxy down", &out);

    let unreachable = format!("http://127.0.0.1:{}", closed_port());
    let out = run(&configured(&unreachable), &allow);
    assert_eq!(code(&out), 69);
    assert_no_sentinel("unreachable", &out);

    let server = ok_server();
    let out = command(
        &via(&proxy, configured(&server.url())),
        &allow,
        &[],
        &["/nonexistent/inshape-cmd", SENTINEL],
    )
    .output()
    .expect("run inshape");
    assert_eq!(code(&out), 71);
    assert_no_sentinel("exec failure", &out);
}

#[test]
fn a_broken_stderr_does_not_stop_the_start() {
    let allow = Allowlist::standard();
    let env = with(pairs(&[("PATH", HOST_PATH)]), &[]);
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let out = command(&env, &allow, &["--optional"], &[CHILD])
        .stderr(Stdio::from(writer))
        .output()
        .expect("run inshape");
    assert_eq!(code(&out), 0);
}

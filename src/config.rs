//! Command-line arguments and settings, read from a map rather than the process environment.
//! Ambient `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` are ignored; the proxy URL is never echoed.
//! `INFISICAL_API_URL` must be `https://`, with no credentials, query or fragment.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use crate::{Error, Secret};

const CLIENT_ID: &str = "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID";
const CLIENT_SECRET: &str = "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET";
const PROJECT_ID: &str = "INFISICAL_PROJECT_ID";
const ENV: &str = "INFISICAL_ENV";
const PATHS: &str = "INFISICAL_PATHS";
const API_URL: &str = "INFISICAL_API_URL";
const PROXY_URL: &str = "INFISICAL_PROXY_URL";

const DEFAULT_API_URL: &str = "https://app.infisical.com";

#[derive(Debug)]
pub enum Mode {
    Unconfigured,
    Configured(Settings),
}

#[derive(Debug)]
pub struct Settings {
    pub client_id: String,
    pub client_secret: Secret,
    pub project_id: String,
    pub env: String,
    pub paths: Vec<String>,
    pub api_url: String,
    pub proxy_url: Option<Secret>,
}

#[derive(Debug)]
pub struct Args {
    pub optional: bool,
    pub allowlist: PathBuf,
    pub command: Vec<OsString>,
}

fn config_err(msg: impl Into<String>) -> Error {
    Error::Config(msg.into())
}

pub fn parse_args(args: &[OsString]) -> Result<Args, Error> {
    let mut optional = false;
    let mut allowlist: Option<PathBuf> = None;
    let mut iter = args.iter();
    let mut command = None;
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("--optional") => optional = true,
            Some("--allowlist") => {
                let file = iter
                    .next()
                    .ok_or_else(|| config_err("--allowlist needs a file"))?;
                if allowlist.replace(PathBuf::from(file)).is_some() {
                    return Err(config_err("--allowlist given more than once"));
                }
            }
            Some("--") => {
                command = Some(iter.cloned().collect::<Vec<_>>());
                break;
            }
            _ => return Err(config_err("unknown argument before --")),
        }
    }
    let allowlist = allowlist.ok_or_else(|| config_err("--allowlist FILE is required"))?;
    let command = command.ok_or_else(|| config_err("missing -- before the command"))?;
    if command.is_empty() {
        return Err(config_err("no command after --"));
    }
    Ok(Args {
        optional,
        allowlist,
        command,
    })
}

/// Missing and empty both read as `None`.
fn get(env: &BTreeMap<OsString, OsString>, name: &str) -> Result<Option<String>, Error> {
    let Some(raw) = env.get(OsString::from(name).as_os_str()) else {
        return Ok(None);
    };
    let value = raw
        .to_str()
        .ok_or_else(|| config_err(format!("{name} is not valid UTF-8")))?;
    if value.is_empty() {
        return Ok(None);
    }
    if value.contains('\0') {
        return Err(config_err(format!("{name} contains a NUL byte")));
    }
    if value.trim().is_empty() {
        return Err(config_err(format!("{name} is only whitespace")));
    }
    Ok(Some(value.to_owned()))
}

pub fn read_settings(env: &BTreeMap<OsString, OsString>) -> Result<Mode, Error> {
    let client_id = get(env, CLIENT_ID)?;
    let client_secret = get(env, CLIENT_SECRET)?;
    let project_id = get(env, PROJECT_ID)?;
    let slug = get(env, ENV)?;

    let (Some(client_id), Some(client_secret), Some(project_id), Some(slug)) = (
        client_id.clone(),
        client_secret.clone(),
        project_id.clone(),
        slug.clone(),
    ) else {
        let missing: Vec<&str> = [
            (CLIENT_ID, client_id.is_some()),
            (CLIENT_SECRET, client_secret.is_some()),
            (PROJECT_ID, project_id.is_some()),
            (ENV, slug.is_some()),
        ]
        .into_iter()
        .filter(|(_, set)| !set)
        .map(|(name, _)| name)
        .collect();
        if missing.len() == 4 {
            return Ok(Mode::Unconfigured);
        }
        return Err(config_err(format!(
            "incomplete configuration, missing: {}",
            missing.join(", ")
        )));
    };

    if slug.chars().any(char::is_whitespace) {
        return Err(config_err(format!("{ENV} must not contain whitespace")));
    }

    let paths = match get(env, PATHS)? {
        Some(raw) => parse_paths(&raw)?,
        None => vec!["/".to_owned()],
    };
    let api_url = match get(env, API_URL)? {
        Some(raw) => parse_api_url(&raw)?,
        None => DEFAULT_API_URL.to_owned(),
    };
    let proxy_url = match get(env, PROXY_URL)? {
        Some(raw) => {
            if !valid_proxy_url(&raw) {
                return Err(config_err(format!(
                    "{PROXY_URL} is not a valid http:// proxy URL"
                )));
            }
            Some(Secret::new(raw))
        }
        None => None,
    };

    Ok(Mode::Configured(Settings {
        client_id,
        client_secret: Secret::new(client_secret),
        project_id,
        env: slug,
        paths,
        api_url,
        proxy_url,
    }))
}

fn canonical_path(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    rest.split('/').all(|seg| {
        !seg.is_empty()
            && seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    })
}

fn parse_paths(raw: &str) -> Result<Vec<String>, Error> {
    let mut paths: Vec<String> = Vec::new();
    for path in raw.split_whitespace() {
        if !canonical_path(path) {
            return Err(config_err(format!(
                "{PATHS}: {path:?} is not a canonical folder path (use /a/b: leading slash, no trailing slash, segments of letters, digits, - and _)"
            )));
        }
        if paths.iter().any(|p| p == path) {
            return Err(config_err(format!("{PATHS}: {path:?} is listed twice")));
        }
        paths.push(path.to_owned());
    }
    Ok(paths)
}

fn parse_api_url(raw: &str) -> Result<String, Error> {
    let rest = raw
        .strip_prefix("https://")
        .or_else(|| {
            if cfg!(feature = "insecure-http-for-tests") {
                raw.strip_prefix("http://")
            } else {
                None
            }
        })
        .ok_or_else(|| config_err(format!("{API_URL} must start with https://")))?;
    let trimmed = raw.trim_end_matches('/');
    let host_part = rest.trim_end_matches('/');
    let bad_char = |c: char| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#' | '@');
    if host_part.is_empty() || host_part.starts_with('/') || host_part.chars().any(bad_char) {
        return Err(config_err(format!(
            "{API_URL} must be a plain base URL: no credentials, query or fragment"
        )));
    }
    Ok(trimmed.to_owned())
}

fn is_ipv6_literal(host: &str) -> bool {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .is_some_and(|inner| {
            !inner.is_empty() && inner.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
        })
}

fn valid_proxy_url(raw: &str) -> bool {
    let Some(rest) = raw.strip_prefix("http://") else {
        return false;
    };
    if rest.matches('@').count() > 1 {
        return false;
    }
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, rest),
    };
    if let Some(user) = userinfo
        && (user.is_empty() || user.starts_with(':'))
    {
        return false;
    }
    let bad = |c: char| c.is_whitespace() || c.is_control() || matches!(c, '/' | '?' | '#');
    if rest.chars().any(bad) {
        return false;
    }
    let Some((host, port)) = hostport.rsplit_once(':') else {
        return false;
    };
    let host_ok = !host.is_empty()
        && !host.contains('@')
        && (is_ipv6_literal(host)
            || host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')));
    let port_ok = !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|p| p > 0);
    host_ok && port_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    fn argv(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(|p| os(p)).collect()
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<OsString, OsString> {
        pairs.iter().map(|(k, v)| (os(k), os(v))).collect()
    }

    const FOUR: [(&str, &str); 4] = [
        ("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "id"),
        ("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "s3cret"),
        ("INFISICAL_PROJECT_ID", "proj"),
        ("INFISICAL_ENV", "prod"),
    ];

    fn with(extra: &[(&str, &str)]) -> BTreeMap<OsString, OsString> {
        let mut pairs: Vec<(&str, &str)> = FOUR.to_vec();
        pairs.extend_from_slice(extra);
        env(&pairs)
    }

    fn settings(map: &BTreeMap<OsString, OsString>) -> Result<Settings, Error> {
        match read_settings(map)? {
            Mode::Configured(s) => Ok(s),
            Mode::Unconfigured => panic!("expected configured"),
        }
    }

    fn is_config_err<T: std::fmt::Debug>(r: Result<T, Error>) -> bool {
        matches!(r, Err(Error::Config(_)))
    }

    #[test]
    fn args_need_allowlist_and_command() {
        let a = parse_args(&argv(&["--allowlist", "f", "--", "cmd", "a"])).unwrap();
        assert_eq!(a.allowlist, PathBuf::from("f"));
        assert_eq!(a.command, argv(&["cmd", "a"]));
        assert!(!a.optional);
        assert!(is_config_err(parse_args(&argv(&["--", "cmd"]))));
        assert!(is_config_err(parse_args(&argv(&[
            "--allowlist",
            "f",
            "cmd"
        ]))));
        assert!(is_config_err(parse_args(&argv(&[
            "--allowlist",
            "f",
            "--"
        ]))));
        assert!(is_config_err(parse_args(&argv(&["--allowlist"]))));
        assert!(is_config_err(parse_args(&argv(&[]))));
    }

    #[test]
    fn args_unknown_flag_refused() {
        assert!(is_config_err(parse_args(&argv(&[
            "--bogus",
            "--allowlist",
            "f",
            "--",
            "cmd"
        ]))));
    }

    #[test]
    fn args_optional_flag() {
        let a = parse_args(&argv(&["--optional", "--allowlist", "f", "--", "cmd"])).unwrap();
        assert!(a.optional);
        let a = parse_args(&argv(&["--allowlist", "f", "--optional", "--", "cmd"])).unwrap();
        assert!(a.optional);
    }

    #[test]
    fn none_of_four_is_unconfigured() {
        assert!(matches!(
            read_settings(&env(&[("PATH", "/bin")])),
            Ok(Mode::Unconfigured)
        ));
    }

    #[test]
    fn some_of_four_is_config_error() {
        let map = env(&[
            ("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "id"),
            ("INFISICAL_ENV", "prod"),
        ]);
        let Err(Error::Config(msg)) = read_settings(&map) else {
            panic!("expected config error");
        };
        assert!(msg.contains("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"));
        assert!(msg.contains("INFISICAL_PROJECT_ID"));
        assert!(!msg.contains("INFISICAL_ENV"));
    }

    #[test]
    fn empty_value_counts_as_missing() {
        let all_empty = env(&[
            ("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", ""),
            ("INFISICAL_ENV", ""),
        ]);
        assert!(matches!(read_settings(&all_empty), Ok(Mode::Unconfigured)));
        let mut map = with(&[]);
        map.insert(os("INFISICAL_PROJECT_ID"), os(""));
        assert!(is_config_err(read_settings(&map)));
    }

    #[test]
    fn whitespace_only_and_nul_values_refused() {
        let mut map = with(&[]);
        map.insert(os("INFISICAL_PROJECT_ID"), os("  "));
        assert!(is_config_err(read_settings(&map)));
        map.insert(os("INFISICAL_PROJECT_ID"), os("a\0b"));
        assert!(is_config_err(read_settings(&map)));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_value_refused() {
        use std::os::unix::ffi::OsStringExt;
        let mut map = with(&[]);
        map.insert(
            os("INFISICAL_PROJECT_ID"),
            OsString::from_vec(vec![0xff, 0xfe]),
        );
        assert!(is_config_err(read_settings(&map)));
    }

    #[test]
    fn configured_values_are_read() {
        let s = settings(&with(&[])).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.client_id, "id");
        assert_eq!(s.client_secret.expose(), "s3cret");
        assert_eq!(s.project_id, "proj");
        assert_eq!(s.env, "prod");
        assert_eq!(s.api_url, "https://app.infisical.com");
        assert!(s.proxy_url.is_none());
    }

    #[test]
    fn paths_default_to_root() {
        assert_eq!(settings(&with(&[])).unwrap().paths, vec!["/"]);
        assert_eq!(
            settings(&with(&[("INFISICAL_PATHS", "")])).unwrap().paths,
            vec!["/"]
        );
    }

    #[test]
    fn paths_split_on_whitespace() {
        let s = settings(&with(&[("INFISICAL_PATHS", "/core  /shared")])).unwrap();
        assert_eq!(s.paths, vec!["/core", "/shared"]);
    }

    #[test]
    fn paths_must_be_canonical() {
        for bad in [
            "/core/",
            "core",
            "//core",
            "/a/../b",
            "/a/./b",
            "/a b/c d",
            "/core /core",
            "/core?x",
            "/a//b",
            "/a.b",
            "/.hidden",
        ] {
            let r = settings(&with(&[("INFISICAL_PATHS", bad)]));
            assert!(is_config_err(r), "{bad:?} should be refused");
        }
        assert!(is_config_err(settings(&with(&[(
            "INFISICAL_PATHS",
            "   "
        )]))));
        for good in ["/", "/a/b-c_d"] {
            assert!(settings(&with(&[("INFISICAL_PATHS", good)])).is_ok());
        }
    }

    #[test]
    fn path_error_names_the_path() {
        let Err(Error::Config(msg)) = settings(&with(&[("INFISICAL_PATHS", "/core/")])) else {
            panic!("expected config error");
        };
        assert!(msg.contains("/core/"));
    }

    #[cfg(not(feature = "insecure-http-for-tests"))]
    #[test]
    fn api_url_https_only() {
        assert!(is_config_err(settings(&with(&[(
            "INFISICAL_API_URL",
            "http://x"
        )]))));
    }

    #[cfg(feature = "insecure-http-for-tests")]
    #[test]
    fn api_url_http_allowed_under_test_feature() {
        let s = settings(&with(&[("INFISICAL_API_URL", "http://127.0.0.1:9")])).unwrap();
        assert_eq!(s.api_url, "http://127.0.0.1:9");
    }

    #[test]
    fn api_url_other_schemes_refused() {
        for bad in ["ftp://x", "x.example", "https://", "https:///p"] {
            assert!(
                is_config_err(settings(&with(&[("INFISICAL_API_URL", bad)]))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn api_url_trailing_slash_trimmed() {
        let s = settings(&with(&[("INFISICAL_API_URL", "https://eu.infisical.com/")])).unwrap();
        assert_eq!(s.api_url, "https://eu.infisical.com");
    }

    #[test]
    fn api_url_with_query_refused() {
        for bad in [
            "https://x.example/?a=b",
            "https://x.example#f",
            "https://u:p@x.example",
        ] {
            assert!(
                is_config_err(settings(&with(&[("INFISICAL_API_URL", bad)]))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn proxy_url_optional_and_never_in_error_text() {
        let s = settings(&with(&[(
            "INFISICAL_PROXY_URL",
            "http://u:pa55@proxy.example:3128",
        )]))
        .unwrap();
        assert_eq!(
            s.proxy_url.as_ref().unwrap().expose(),
            "http://u:pa55@proxy.example:3128"
        );
        assert!(format!("{s:?}").find("pa55").is_none());
        let plain = settings(&with(&[(
            "INFISICAL_PROXY_URL",
            "http://proxy.example:3128",
        )]));
        assert!(plain.is_ok());

        let Err(Error::Config(msg)) =
            settings(&with(&[("INFISICAL_PROXY_URL", "http://user:pa55@")]))
        else {
            panic!("expected config error");
        };
        assert!(!msg.contains("pa55"));
        assert!(!msg.contains("user"));
        assert!(msg.contains("INFISICAL_PROXY_URL"));
    }

    #[test]
    fn proxy_url_forms_refused() {
        for bad in [
            "https://proxy.example:3128",
            "socks5://proxy.example:1080",
            "proxy.example:3128",
            "http://proxy.example",
            "http://proxy.example:0",
            "http://proxy.example:99999",
            "http://proxy.example:3128/path",
            "http://:3128",
            "http://@proxy.example:3128",
            "http://u:p@ss@proxy.example:3128",
            "http://u@v@proxy.example:3128",
            "http://:3128",
            "http://u:p@:3128",
            "http://[]:3128",
            "http://[zz]:3128",
        ] {
            assert!(
                is_config_err(settings(&with(&[("INFISICAL_PROXY_URL", bad)]))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn ipv6_proxy_host_accepted() {
        assert!(settings(&with(&[("INFISICAL_PROXY_URL", "http://[::1]:3128")])).is_ok());
    }

    #[test]
    fn proxy_error_never_echoes_the_url() {
        for bad in ["http://u:p@ss-SENTINEL@h:1", "http://u:SENTINEL@[]:1"] {
            let Err(Error::Config(msg)) = settings(&with(&[("INFISICAL_PROXY_URL", bad)])) else {
                panic!("expected config error");
            };
            assert!(!msg.contains("SENTINEL"), "{msg}");
        }
    }

    #[test]
    fn ambient_proxy_vars_ignored() {
        let s = settings(&with(&[
            ("HTTPS_PROXY", "http://evil.example:1"),
            ("https_proxy", "http://evil.example:1"),
            ("ALL_PROXY", "http://evil.example:1"),
        ]))
        .unwrap();
        assert!(s.proxy_url.is_none());
        assert!(!format!("{s:?}").contains("evil"));
    }

    #[test]
    fn env_slug_exact() {
        let mut map = with(&[]);
        map.insert(os("INFISICAL_ENV"), os("staging"));
        assert_eq!(settings(&map).unwrap().env, "staging");
        for bad in [" prod", "prod ", "pr od", "prod\n"] {
            map.insert(os("INFISICAL_ENV"), os(bad));
            assert!(is_config_err(read_settings(&map)), "{bad:?}");
        }
    }
}

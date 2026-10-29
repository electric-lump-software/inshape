//! The main flow: read the settings, fetch and check the secrets, revoke the
//! token, then replace this process with the command.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::allowlist::{self, Allowlist};
use crate::checks::{self, Loaded};
use crate::config::{self, Mode};
use crate::error::log;
use crate::infisical::{self, Client};
use crate::{Error, Secret};

const CANARY_PREFIX: &str = "INFISICAL_CANARY_";
const OWN_PREFIX: &str = "INFISICAL_";

type Env = Vec<(OsString, OsString)>;

/// Refuses host variables the allowlist names, so stale values never shadow fetched ones.
pub fn child_env(
    host: &BTreeMap<OsString, OsString>,
    loaded: &Loaded,
    allow: &Allowlist,
) -> Result<Env, Error> {
    refuse_host_clashes(host, allow)?;
    let mut env = without_own_names(host);
    env.extend(
        loaded
            .values
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value.expose()))),
    );
    Ok(env)
}

fn refuse_host_clashes(
    host: &BTreeMap<OsString, OsString>,
    allow: &Allowlist,
) -> Result<(), Error> {
    let clashes: Vec<&str> = host
        .keys()
        .filter_map(|name| name.to_str())
        .filter(|name| allow.allows(name) || name.starts_with(CANARY_PREFIX))
        .collect();
    if clashes.is_empty() {
        return Ok(());
    }
    Err(Error::Config(format!(
        "the host already sets {}; remove it so only the Infisical value is used",
        clashes.join(", ")
    )))
}

fn without_own_names(host: &BTreeMap<OsString, OsString>) -> Env {
    host.iter()
        .filter(|(name, _)| !name.as_encoded_bytes().starts_with(OWN_PREFIX.as_bytes()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

pub fn run(args: Vec<OsString>, host: BTreeMap<OsString, OsString>) -> Error {
    match prepare(&args, host) {
        Ok((command, env)) => exec(&command, env),
        Err(e) => e,
    }
}

fn prepare(
    args: &[OsString],
    host: BTreeMap<OsString, OsString>,
) -> Result<(Vec<OsString>, Env), Error> {
    let args = config::parse_args(args)?;
    let allow = allowlist::load(&args.allowlist)?;
    let settings = match config::read_settings(&host)? {
        Mode::Configured(settings) => settings,
        Mode::Unconfigured if args.optional => {
            log("Infisical not configured; starting without it");
            return Ok((args.command, without_own_names(&host)));
        }
        Mode::Unconfigured => {
            return Err(Error::Config(
                "Infisical is not configured: set INFISICAL_UNIVERSAL_AUTH_CLIENT_ID, \
                 INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET, INFISICAL_PROJECT_ID and \
                 INFISICAL_ENV, or pass --optional to start without it"
                    .to_owned(),
            ));
        }
    };

    refuse_host_clashes(&host, &allow)?;
    let client = Client::new(&settings)?;
    let token = client.login()?;
    let fetched = fetch_all(&client, &token, &settings.paths);
    revoke(&client, &token);
    let folders = fetched?;

    let loaded = checks::check(&settings.env, &folders, &allow)?;
    let env = child_env(&host, &loaded, &allow)?;
    log(&summary(&loaded));
    Ok((args.command, env))
}

fn fetch_all(
    client: &Client,
    token: &Secret,
    paths: &[String],
) -> Result<Vec<(String, Vec<infisical::RawSecret>)>, Error> {
    paths
        .iter()
        .map(|path| Ok((path.clone(), client.fetch(token, path)?)))
        .collect()
}

fn revoke(client: &Client, token: &Secret) {
    if let Err(e) = client.revoke(token) {
        log(&revoke_warning(&e));
    }
}

fn revoke_warning(err: &Error) -> String {
    let what = match infisical::http_status(err) {
        Some(status) => format!("status {status}"),
        None => "no usable answer".to_owned(),
    };
    format!("could not revoke the sign-in token ({what}); it will expire on its own")
}

fn summary(loaded: &Loaded) -> String {
    let folders: Vec<String> = loaded
        .per_path
        .iter()
        .map(|(path, count)| format!("{path} ({count})"))
        .collect();
    format!(
        "loaded {} secrets from {}; canaries: {}",
        loaded.values.len(),
        folders.join(", "),
        loaded.canaries.join(" ")
    )
}

fn exec(command: &[OsString], env: Env) -> Error {
    let program: &OsStr = &command[0];
    let err = Command::new(program)
        .args(&command[1..])
        .env_clear()
        .envs(env)
        .exec();
    Error::Exec(format!(
        "could not start {}: {}",
        program.to_string_lossy(),
        err.kind()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    fn host(pairs: &[(&str, &str)]) -> BTreeMap<OsString, OsString> {
        pairs.iter().map(|(k, v)| (os(k), os(v))).collect()
    }

    fn loaded(pairs: &[(&str, &str)]) -> Loaded {
        Loaded {
            values: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), Secret::new((*v).to_owned())))
                .collect(),
            canaries: pairs
                .iter()
                .filter(|(k, _)| k.starts_with(CANARY_PREFIX))
                .map(|(k, _)| (*k).to_owned())
                .collect(),
            per_path: vec![("/core".to_owned(), pairs.len())],
        }
    }

    fn allow() -> Allowlist {
        allowlist::parse("SECRET_X\nOTHER\n").unwrap()
    }

    fn config_msg(r: Result<Env, Error>) -> String {
        match r {
            Err(Error::Config(m)) => m,
            other => panic!("expected config error, got {other:?}"),
        }
    }

    #[test]
    fn drops_own_names_then_adds_values_and_canaries() {
        let h = host(&[
            ("PATH", "/bin"),
            ("INFISICAL_ENV", "prod"),
            ("INFISICAL_PROXY_URL", "http://u:p@h:1"),
            ("INFISICAL_other", "x"),
        ]);
        let l = loaded(&[("SECRET_X", "v"), ("INFISICAL_CANARY_CORE", "c")]);
        let mut env = child_env(&h, &l, &allow()).unwrap();
        env.sort();
        assert_eq!(
            env,
            vec![
                (os("INFISICAL_CANARY_CORE"), os("c")),
                (os("PATH"), os("/bin")),
                (os("SECRET_X"), os("v")),
            ]
        );
    }

    #[test]
    fn host_allowlisted_name_refused_by_name_only() {
        let h = host(&[("OTHER", "SENTINEL-9f2c"), ("SECRET_X", "SENTINEL-9f2c")]);
        let m = config_msg(child_env(&h, &loaded(&[("SECRET_X", "v")]), &allow()));
        assert!(m.contains("OTHER, SECRET_X"), "{m}");
        assert!(!m.contains("9f2c"), "{m}");
    }

    #[test]
    fn host_canary_refused() {
        for name in ["INFISICAL_CANARY_OLD", "INFISICAL_CANARY_lower"] {
            let h = host(&[(name, "SENTINEL-9f2c")]);
            let m = config_msg(child_env(&h, &loaded(&[]), &allow()));
            assert!(m.contains(name), "{m}");
            assert!(!m.contains("9f2c"), "{m}");
        }
    }

    #[test]
    fn name_differing_in_case_is_not_a_clash() {
        let h = host(&[("secret_x", "host")]);
        let env = child_env(&h, &loaded(&[("SECRET_X", "v")]), &allow()).unwrap();
        assert!(env.contains(&(os("secret_x"), os("host"))));
        assert!(env.contains(&(os("SECRET_X"), os("v"))));
    }

    #[test]
    fn non_utf8_host_vars_pass_through() {
        use std::os::unix::ffi::OsStringExt;
        let odd = OsString::from_vec(vec![0xff, 0xfe]);
        let mut h = host(&[]);
        h.insert(odd.clone(), odd.clone());
        h.insert(os("ODD"), odd.clone());
        let env = child_env(&h, &loaded(&[]), &allow()).unwrap();
        assert!(env.contains(&(odd.clone(), odd.clone())));
        assert!(env.contains(&(os("ODD"), odd)));
    }

    #[test]
    fn summary_line() {
        let mut l = loaded(&[
            ("SECRET_X", "v"),
            ("INFISICAL_CANARY_A", "c"),
            ("INFISICAL_CANARY_B", "c"),
        ]);
        l.per_path = vec![("/a".to_owned(), 2), ("/b".to_owned(), 1)];
        assert_eq!(
            summary(&l),
            "loaded 3 secrets from /a (2), /b (1); canaries: INFISICAL_CANARY_A INFISICAL_CANARY_B"
        );
    }

    #[test]
    fn revoke_warning_text() {
        assert_eq!(
            revoke_warning(&Error::Unavailable(
                "revoking the token: Infisical answered HTTP 502".into()
            )),
            "could not revoke the sign-in token (status 502); it will expire on its own"
        );
        assert_eq!(
            revoke_warning(&Error::Unavailable(
                "revoking the token: connection refused".into()
            )),
            "could not revoke the sign-in token (no usable answer); it will expire on its own"
        );
    }

    #[test]
    fn exec_failure_names_command_only() {
        let err = exec(
            &[os("/nonexistent/inshape-cmd"), os("--secret-arg")],
            Vec::new(),
        );
        assert_eq!(err.exit_code(), 71);
        assert!(err.to_string().contains("/nonexistent/inshape-cmd"));
        assert!(!err.to_string().contains("--secret-arg"));
    }
}

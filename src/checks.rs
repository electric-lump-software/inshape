//! Decides whether the fetched folders are acceptable before anything is exported.
//!
//! Every problem across every folder is collected first, so one start shows them all.
//! Messages name folders and secret names only, never values.

use std::collections::{BTreeMap, BTreeSet};

use crate::allowlist::{Allowlist, is_canary, valid_name};
use crate::infisical::RawSecret;
use crate::{Error, Secret};

const HIDDEN_MARKER: &str = "<hidden-by-infisical>";

#[derive(Debug)]
pub struct Loaded {
    /// Includes canaries, which the child also receives.
    pub values: BTreeMap<String, Secret>,
    pub canaries: Vec<String>,
    pub per_path: Vec<(String, usize)>,
}

pub fn check(
    env: &str,
    folders: &[(String, Vec<RawSecret>)],
    allow: &Allowlist,
) -> Result<Loaded, Error> {
    let mut problems: Vec<String> = Vec::new();
    let mut values: BTreeMap<String, Secret> = BTreeMap::new();
    let mut first_seen: BTreeMap<&str, &str> = BTreeMap::new();
    let mut canaries: BTreeSet<String> = BTreeSet::new();
    let mut per_path = Vec::new();

    if folders.is_empty() {
        problems.push("no folders were fetched".to_owned());
    }
    for (path, secrets) in folders {
        per_path.push((path.clone(), secrets.len()));
        if secrets.is_empty() {
            problems.push(format!("{path}: the folder has no secrets"));
            continue;
        }
        let mut sorted: Vec<&RawSecret> = secrets.iter().collect();
        sorted.sort_by(|a, b| a.key.cmp(&b.key));
        let mut seen_here: BTreeSet<&str> = BTreeSet::new();
        let mut has_canary = false;

        for s in sorted {
            let name = s.key.as_str();
            if !valid_name(name) {
                problems.push(format!("{path}: a secret name that is not valid"));
                continue;
            }
            if !seen_here.insert(name) {
                problems.push(format!("{path}: {name} appears more than once"));
                continue;
            }
            if !allow.allows(name) {
                problems.push(format!("{path}: {name} is not in the allowlist"));
            }
            let canary = is_canary(name);
            has_canary |= canary;
            if let Some(other) = first_seen.get(name) {
                let what = if canary { "canary " } else { "" };
                problems.push(format!("{path}: {what}{name} is also in {other}"));
            } else {
                first_seen.insert(name, path);
            }
            match s.environment.as_deref() {
                None => problems.push(format!("{path}: {name} came back with no environment")),
                Some(e) if e != env => {
                    problems.push(format!("{path}: {name} came back from another environment"))
                }
                Some(_) => {}
            }
            match s.secret_path.as_deref() {
                None => problems.push(format!("{path}: {name} came back with no folder path")),
                Some(p) if p != path => {
                    problems.push(format!("{path}: {name} came back from another folder"))
                }
                Some(_) => {}
            }
            let value = s.value.expose();
            if s.value_hidden || value == HIDDEN_MARKER {
                problems.push(format!("{path}: {name} has a hidden value"));
            } else if value.is_empty() {
                problems.push(format!("{path}: {name} has an empty value"));
            } else if value.trim().is_empty() {
                problems.push(format!("{path}: {name} has a whitespace-only value"));
            } else if value.contains('\0') {
                problems.push(format!("{path}: {name} has a NUL byte in its value"));
            }
            if canary {
                canaries.insert(name.to_owned());
            }
            values
                .entry(name.to_owned())
                .or_insert_with(|| s.value.clone());
        }
        if !has_canary {
            problems.push(format!("{path}: no INFISICAL_CANARY_ secret"));
        }
    }

    if !problems.is_empty() {
        return Err(Error::Refused(format!(
            "refusing to start: {}",
            problems.join("; ")
        )));
    }
    Ok(Loaded {
        values,
        canaries: canaries.into_iter().collect(),
        per_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist;

    const ENV: &str = "prod";

    fn allow() -> Allowlist {
        allowlist::parse("SECRET_X\nSTRIPE_KEY\nOTHER\n").unwrap()
    }

    fn raw(path: &str, key: &str, value: &str) -> RawSecret {
        RawSecret {
            key: key.into(),
            value: Secret::new(value.into()),
            environment: Some(ENV.into()),
            secret_path: Some(path.into()),
            value_hidden: false,
        }
    }

    fn canary(path: &str, name: &str) -> RawSecret {
        raw(path, name, "present")
    }

    fn folder(path: &str, secrets: Vec<RawSecret>) -> (String, Vec<RawSecret>) {
        (path.into(), secrets)
    }

    fn refused(folders: &[(String, Vec<RawSecret>)]) -> String {
        match check(ENV, folders, &allow()) {
            Err(Error::Refused(m)) => m,
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    fn one(secrets: Vec<RawSecret>) -> String {
        let mut all = vec![canary("/core", "INFISICAL_CANARY_CORE")];
        all.extend(secrets);
        refused(&[folder("/core", all)])
    }

    #[test]
    fn no_folders_refused() {
        let m = refused(&[]);
        assert!(m.contains("no folders were fetched"), "{m}");
    }

    #[test]
    fn empty_folder_refused() {
        let m = refused(&[folder("/core", vec![])]);
        assert!(m.contains("/core: the folder has no secrets"), "{m}");
    }

    #[test]
    fn folder_without_own_canary_refused() {
        let m = refused(&[
            folder("/core", vec![canary("/core", "INFISICAL_CANARY_CORE")]),
            folder("/shared", vec![raw("/shared", "OTHER", "v")]),
        ]);
        assert!(m.contains("/shared: no INFISICAL_CANARY_ secret"), "{m}");
        assert!(!m.contains("/core:"), "{m}");
    }

    #[test]
    fn canary_repeated_across_folders_refused() {
        let m = refused(&[
            folder("/core", vec![canary("/core", "INFISICAL_CANARY_A")]),
            folder("/shared", vec![canary("/shared", "INFISICAL_CANARY_A")]),
        ]);
        assert!(
            m.contains("/shared: canary INFISICAL_CANARY_A is also in /core"),
            "{m}"
        );
    }

    #[test]
    fn name_not_allowed_refused_and_named() {
        let m = one(vec![raw("/core", "SECRET_Z", "v")]);
        assert!(m.contains("/core: SECRET_Z is not in the allowlist"), "{m}");
    }

    #[test]
    fn invalid_name_refused() {
        let m = one(vec![raw("/core", "sk_live_SENTINEL-9f2c", "v")]);
        assert!(m.contains("/core: a secret name that is not valid"), "{m}");
        assert!(!m.contains("sk_live"), "{m}");
        assert!(!m.contains("9f2c"), "{m}");
    }

    #[test]
    fn duplicate_within_folder_refused() {
        let m = one(vec![raw("/core", "OTHER", "a"), raw("/core", "OTHER", "b")]);
        assert!(m.contains("/core: OTHER appears more than once"), "{m}");
    }

    #[test]
    fn same_name_in_two_folders_refused() {
        let m = refused(&[
            folder(
                "/core",
                vec![
                    canary("/core", "INFISICAL_CANARY_A"),
                    raw("/core", "OTHER", "a"),
                ],
            ),
            folder(
                "/shared",
                vec![
                    canary("/shared", "INFISICAL_CANARY_B"),
                    raw("/shared", "OTHER", "b"),
                ],
            ),
        ]);
        assert!(m.contains("/shared: OTHER is also in /core"), "{m}");
    }

    #[test]
    fn hidden_value_refused() {
        let mut flagged = raw("/core", "OTHER", "real");
        flagged.value_hidden = true;
        let m = one(vec![
            flagged,
            raw("/core", "STRIPE_KEY", "<hidden-by-infisical>"),
        ]);
        assert!(m.contains("/core: OTHER has a hidden value"), "{m}");
        assert!(m.contains("/core: STRIPE_KEY has a hidden value"), "{m}");
    }

    #[test]
    fn empty_value_refused() {
        let m = one(vec![raw("/core", "OTHER", "")]);
        assert!(m.contains("/core: OTHER has an empty value"), "{m}");
    }

    #[test]
    fn whitespace_only_value_refused() {
        let m = one(vec![raw("/core", "OTHER", " \t\n\u{a0}")]);
        assert!(
            m.contains("/core: OTHER has a whitespace-only value"),
            "{m}"
        );
    }

    #[test]
    fn nul_in_value_refused() {
        let m = one(vec![raw("/core", "OTHER", "a\0b")]);
        assert!(
            m.contains("/core: OTHER has a NUL byte in its value"),
            "{m}"
        );
    }

    #[test]
    fn environment_mismatch_refused() {
        let mut s = raw("/core", "OTHER", "v");
        s.environment = Some("dev".into());
        let m = one(vec![s]);
        assert!(
            m.contains("/core: OTHER came back from another environment"),
            "{m}"
        );
        assert!(!m.contains("dev"), "{m}");
    }

    #[test]
    fn secret_path_mismatch_refused() {
        let mut s = raw("/core", "OTHER", "v");
        s.secret_path = Some("/elsewhere".into());
        let m = one(vec![s]);
        assert!(
            m.contains("/core: OTHER came back from another folder"),
            "{m}"
        );
    }

    #[test]
    fn missing_environment_or_path_refused() {
        let mut a = raw("/core", "OTHER", "v");
        a.environment = None;
        let mut b = raw("/core", "STRIPE_KEY", "v");
        b.secret_path = None;
        let m = one(vec![a, b]);
        assert!(
            m.contains("/core: OTHER came back with no environment"),
            "{m}"
        );
        assert!(
            m.contains("/core: STRIPE_KEY came back with no folder path"),
            "{m}"
        );
    }

    #[test]
    fn all_problems_reported_together() {
        let m = refused(&[
            folder("/core", vec![raw("/core", "SECRET_Z", "v")]),
            folder(
                "/shared",
                vec![
                    canary("/shared", "INFISICAL_CANARY_S"),
                    raw("/shared", "STRIPE_KEY", ""),
                ],
            ),
        ]);
        assert_eq!(
            m,
            "refusing to start: /core: SECRET_Z is not in the allowlist; \
             /core: no INFISICAL_CANARY_ secret; /shared: STRIPE_KEY has an empty value"
        );
    }

    #[test]
    fn ok_case_returns_values_canaries_and_counts() {
        let loaded = check(
            ENV,
            &[
                folder(
                    "/core",
                    vec![
                        raw("/core", "SECRET_X", "x"),
                        canary("/core", "INFISICAL_CANARY_CORE"),
                    ],
                ),
                folder(
                    "/shared",
                    vec![
                        canary("/shared", "INFISICAL_CANARY_AAA"),
                        raw("/shared", "STRIPE_KEY", "k"),
                    ],
                ),
            ],
            &allow(),
        )
        .unwrap();
        assert_eq!(loaded.values.len(), 4);
        assert_eq!(loaded.values["SECRET_X"].expose(), "x");
        assert!(loaded.values.contains_key("INFISICAL_CANARY_CORE"));
        assert_eq!(
            loaded.canaries,
            vec!["INFISICAL_CANARY_AAA", "INFISICAL_CANARY_CORE"]
        );
        assert_eq!(
            loaded.per_path,
            vec![("/core".to_owned(), 2), ("/shared".to_owned(), 2)]
        );
    }

    #[test]
    fn refusal_text_never_contains_value() {
        let s = "SENTINEL-9f2c";
        let mut hidden = raw("/core", "OTHER", s);
        hidden.value_hidden = true;
        let mut wrong_env = raw("/core", "STRIPE_KEY", s);
        wrong_env.environment = Some("dev".into());
        let m = one(vec![
            hidden,
            wrong_env,
            raw("/core", "SECRET_Z", s),
            raw("/core", "bad name", s),
            raw("/core", "SECRET_X", &format!("{s}\0")),
            raw("/core", "SECRET_X", s),
        ]);
        assert!(!m.contains("SENTINEL"), "{m}");
        assert!(!m.contains("9f2c"), "{m}");
    }
}

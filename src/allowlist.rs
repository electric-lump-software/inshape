//! The allowlist file: one secret name per line, `#` comments, blank lines ignored.
//! Canary names are allowed without being listed.

use std::collections::BTreeSet;
use std::path::Path;

use crate::Error;

#[derive(Debug)]
pub struct Allowlist(BTreeSet<String>);

impl Allowlist {
    pub fn allows(&self, name: &str) -> bool {
        self.0.contains(name) || is_canary(name)
    }
}

pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

pub fn is_canary(name: &str) -> bool {
    name.strip_prefix("INFISICAL_CANARY_").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    })
}

fn is_denied(name: &str) -> bool {
    name == "PATH"
        || name == "HOME"
        || name.starts_with("LD_")
        || name.starts_with("ERL_")
        || name.starts_with("RELEASE_")
        || name.starts_with("INFISICAL_")
        || name.ends_with("DATABASE_URL")
}

pub fn parse(text: &str) -> Result<Allowlist, Error> {
    let mut names = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        let name = line.trim();
        if name.is_empty() || name.starts_with('#') {
            continue;
        }
        let line_no = index + 1;
        if !valid_name(name) {
            let reason = if name.contains('=') {
                "looks like NAME=value; list names only"
            } else {
                "not a valid name (use A-Z, 0-9 and _, starting with a letter)"
            };
            return Err(Error::Config(format!("allowlist line {line_no}: {reason}")));
        }
        if is_denied(name) {
            return Err(Error::Config(format!(
                "allowlist line {line_no}: {name} is a denied name"
            )));
        }
        if !names.insert(name.to_owned()) {
            return Err(Error::Config(format!(
                "allowlist line {line_no}: {name} is listed twice"
            )));
        }
    }
    if names.is_empty() {
        return Err(Error::Config("allowlist has no names".to_owned()));
    }
    Ok(Allowlist(names))
}

pub fn load(path: &Path) -> Result<Allowlist, Error> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::Config(format!(
            "cannot read allowlist {}: {}",
            path.display(),
            e.kind()
        ))
    })?;
    parse(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_msg(r: Result<Allowlist, Error>) -> String {
        match r {
            Err(Error::Config(m)) => m,
            other => panic!("expected config error, got {other:?}"),
        }
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let list =
            parse("# top\n\n  SECRET_KEY_BASE  \n   # indented comment\nAUTH_SECRET\n").unwrap();
        assert!(list.allows("SECRET_KEY_BASE"));
        assert!(list.allows("AUTH_SECRET"));
        assert!(!list.allows("OTHER"));
    }

    #[test]
    fn invalid_name_refused() {
        for bad in ["lower", "1ABC", "sk_live_SENTINEL9f2c"] {
            let msg = config_msg(parse(bad));
            assert!(msg.contains("line 1"), "{msg}");
            assert!(msg.contains("not a valid name"), "{msg}");
            assert!(!msg.contains(bad), "{msg}");
        }
        for bad in [
            "sk_live_SENTINEL9f2c",
            "A-B",
            "A B",
            "A=SENTINEL-9f2c",
            "SECRET_KEY_BASE=SENTINEL-9f2c",
        ] {
            let msg = config_msg(parse(bad));
            assert!(msg.contains("line 1"), "{msg}");
            assert!(!msg.contains(bad), "{msg}");
            assert!(!msg.contains("SENTINEL"), "{msg}");
            assert!(!msg.contains("9f2c"), "{msg}");
        }
        assert!(config_msg(parse("A=SENTINEL-9f2c")).contains("looks like NAME=value"));
    }

    #[test]
    fn duplicate_refused() {
        assert!(config_msg(parse("A\nB\nA\n")).contains('A'));
    }

    #[test]
    fn empty_allowlist_refused() {
        assert!(matches!(parse(""), Err(Error::Config(_))));
        assert!(matches!(
            parse("# only a comment\n\n"),
            Err(Error::Config(_))
        ));
    }

    #[test]
    fn denied_names_refused() {
        for name in [
            "LD_PRELOAD",
            "PATH",
            "HOME",
            "ERL_FLAGS",
            "RELEASE_COOKIE",
            "INFISICAL_TOKEN",
            "DATABASE_URL",
            "MIGRATION_DATABASE_URL",
        ] {
            let msg = config_msg(parse(&format!("OK_NAME\n{name}\n")));
            assert!(msg.contains(name), "{msg}");
        }
    }

    #[test]
    fn similar_names_are_not_denied() {
        assert!(parse("PATHS\nHOMEPAGE\nLDAP_URL\nDATABASE_URL_X\n").is_ok());
    }

    #[test]
    fn canary_allowed_without_listing() {
        let list = parse("A\n").unwrap();
        assert!(list.allows("INFISICAL_CANARY_CORE"));
        assert!(is_canary("INFISICAL_CANARY_CORE"));
        assert!(!is_canary("INFISICAL_CANARY_"));
        assert!(!is_canary("INFISICAL_CANARY_core"));
        assert!(!is_canary("INFISICAL_OTHER"));
    }

    #[test]
    fn canary_in_file_refused() {
        assert!(config_msg(parse("A\nINFISICAL_CANARY_CORE\n")).contains("INFISICAL_CANARY_CORE"));
    }

    #[test]
    fn valid_name_pattern() {
        assert!(valid_name("A"));
        assert!(valid_name("A_1"));
        assert!(!valid_name(""));
        assert!(!valid_name("_A"));
        assert!(!valid_name("a"));
    }

    #[test]
    fn missing_file_is_config_error() {
        let r = load(Path::new("/nonexistent/inshape/allowlist"));
        assert!(matches!(r, Err(Error::Config(_))));
    }

    #[test]
    fn load_reads_a_file() {
        let dir = std::env::temp_dir().join(format!("inshape-allowlist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("list");
        std::fs::write(&file, "SECRET_KEY_BASE\n").unwrap();
        let list = load(&file).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(list.allows("SECRET_KEY_BASE"));
    }
}

use std::fmt;
use std::io::Write;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Config(String),
    Refused(String),
    Unavailable(String),
    Auth(String),
    Exec(String),
}

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Config(_) => 64,
            Error::Refused(_) => 65,
            Error::Unavailable(_) => 69,
            Error::Auth(_) => 77,
            Error::Exec(_) => 71,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Error::Config(m)
            | Error::Refused(m)
            | Error::Unavailable(m)
            | Error::Auth(m)
            | Error::Exec(m) => m,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for Error {}

pub fn log(msg: &str) {
    let _ = writeln!(std::io::stderr(), "inshape: {msg}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_sysexits() {
        assert_eq!(Error::Config("x".into()).exit_code(), 64);
        assert_eq!(Error::Refused("x".into()).exit_code(), 65);
        assert_eq!(Error::Unavailable("x".into()).exit_code(), 69);
        assert_eq!(Error::Auth("x".into()).exit_code(), 77);
        assert_eq!(Error::Exec("x".into()).exit_code(), 71);
    }

    #[test]
    fn display_is_the_message_only() {
        assert_eq!(Error::Refused("nope".into()).to_string(), "nope");
    }
}

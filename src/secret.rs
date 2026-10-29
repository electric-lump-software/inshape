use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let shown = format!("{:?}", Secret::new("hunter2".into()));
        assert_eq!(shown, "Secret(***)");
        assert!(!shown.contains("hunter2"));
    }

    #[test]
    fn expose_returns_the_value() {
        assert_eq!(Secret::new("hunter2".into()).expose(), "hunter2");
    }
}

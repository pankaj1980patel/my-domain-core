//! Core error type. Display renders the bare message so platform adapters can
//! surface it to the UI exactly as the previous `Result<_, String>` code did.

use std::fmt;

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Clone)]
pub struct CoreError(pub String);

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CoreError {}

impl From<String> for CoreError {
    fn from(s: String) -> Self {
        CoreError(s)
    }
}

impl From<&str> for CoreError {
    fn from(s: &str) -> Self {
        CoreError(s.to_string())
    }
}

impl From<CoreError> for String {
    fn from(e: CoreError) -> Self {
        e.0
    }
}

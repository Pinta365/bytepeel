use std::fmt;

/// A machine-readable diagnostic: used both for hard errors and node warnings.
///
/// `code` is a stable SCREAMING_SNAKE identifier (see `docs/DESIGN.md`);
/// `offset` is a byte offset into the buffer being decoded, when known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diag {
    pub code: &'static str,
    pub message: String,
    pub offset: Option<usize>,
}

impl Diag {
    pub fn new(code: &'static str, message: impl Into<String>, offset: Option<usize>) -> Self {
        Self {
            code,
            message: message.into(),
            offset,
        }
    }
}

impl fmt::Display for Diag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)?;
        if let Some(o) = self.offset {
            write!(f, " (offset {o})")?;
        }
        Ok(())
    }
}

impl std::error::Error for Diag {}

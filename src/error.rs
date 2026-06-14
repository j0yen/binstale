//! Error types for binstale.

use thiserror::Error;

/// All errors that binstale can produce.
#[derive(Debug, Error)]
pub enum BinstaleError {
    /// A process with the given PID does not exist in `/proc`.
    #[error("process not found: PID {pid}")]
    ProcessNotFound {
        /// The PID that was not found.
        pid: u32,
    },

    /// Failed to read a file from `/proc`.
    #[error("failed to read /proc path {path}: {source}")]
    ProcRead {
        /// The path that could not be read.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to parse a value from `/proc`.
    #[error("parse error: {context}")]
    ParseError {
        /// Description of what failed to parse.
        context: String,
    },

    /// Failed to read an xattr from an on-disk path.
    #[error("xattr read failed for {path}: {source}")]
    XattrRead {
        /// The file path whose xattr read failed.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to write an xattr to an on-disk path.
    #[error("xattr write failed for {path}: {source}")]
    XattrWrite {
        /// The file path whose xattr write failed.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The system clock is before the Unix epoch.
    #[error("system clock is before Unix epoch: {context}")]
    ClockError {
        /// Description of the error.
        context: String,
    },

    /// An invalid regex was provided.
    #[error("invalid regex: {source}")]
    InvalidRegex {
        /// The underlying regex error.
        #[from]
        source: regex::Error,
    },
}

/// Exit code constants matching the PRD specification.
pub mod exit_code {
    /// All scanned processes are fresh.
    pub const FRESH: i32 = 0;
    /// At least one process has a non-fresh verdict.
    pub const STALE: i32 = 1;
    /// Usage error or I/O error.
    pub const ERROR: i32 = 2;
}

//! `binstale` library — public API for integration tests and external consumers.
//!
//! Exposes the core modules so integration tests in `tests/` can access
//! the verdict engine, fleet aggregate, and output formatting without
//! going through the binary's `main()`.

pub mod error;
pub mod fleet;
pub mod output;
pub mod proc;
pub mod source;
pub mod verdict;

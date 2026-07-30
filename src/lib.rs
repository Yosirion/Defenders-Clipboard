//! Library crate for Defenders Clipboard.
//!
//! Splitting the app into a lib + thin bin (`main.rs`) lets `tests/` run true
//! integration tests against the public API, in addition to the unit tests
//! that live next to each module (`src/<module>/tests.rs`).

pub mod api;
pub mod app;
pub mod clipboard_listener;
pub mod events;
pub mod transformers;

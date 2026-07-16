//! Candidate-memory-only implementation boundary.
//!
//! Domain operations may be crate-visible; generic normalization is restricted
//! to this module and its implementation children.

pub(crate) mod extraction_safety;
pub(crate) mod fingerprint;
mod normalization;

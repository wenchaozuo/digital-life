//! D28 capability-authority foundation.
//!
//! This module contains only typed capability descriptors, the durable
//! user-authorization contract, and a non-executable grant candidate.  It has
//! no command, process, filesystem, network, browser, provider, or agent
//! execution surface.

pub(crate) mod authorization;
pub(crate) mod descriptor;

#[cfg(test)]
mod d29h1;

#[cfg(test)]
mod vita_tool_adapter;

pub(crate) use descriptor::CapabilityRegistry;

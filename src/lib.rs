//! `mcp-lock`: a proxy that pins MCP tool definitions in a lockfile and blocks tools whose
//! definitions drift.

pub mod canonical;
pub mod classify;
pub mod client;
pub mod fingerprint;
pub mod interceptor;
pub mod lockfile;
pub mod proxy;
pub mod transport;

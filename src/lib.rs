//! `mcp-lock`: a proxy that pins MCP tool definitions in a lockfile and blocks tools whose
//! definitions drift.

pub mod canonical;
pub mod fingerprint;
pub mod proxy;
pub mod transport;

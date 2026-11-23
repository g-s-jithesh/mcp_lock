use anyhow::{bail, Context};
use clap::{Args, Parser, Subcommand};
use mcp_lock::classify::{check, visible, Severity};
use mcp_lock::fingerprint::{fingerprint_tools, Pinned};
use mcp_lock::interceptor::Interceptor;
use mcp_lock::lockfile::{self, Lockfile};
use mcp_lock::transport::stdio::StdioTransport;
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use tokio::time::timeout;

/// How long a server gets to answer `initialize` + `tools/list` (npx may download first).
const LIST_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a server gets to exit after we close its stdin, before it is killed.
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Proxy a stdio MCP server, hiding tools that are new or changed since approval
    /// and rejecting calls to them.
    Run(ServerArgs),
    /// Show how the server's tools differ from the lockfile. Changes nothing.
    /// Exits 1 if anything drifted.
    Status(ServerArgs),
    /// Show exactly what changed in drifted tools, field by field. Changes nothing.
    /// Exits 1 if anything drifted.
    Diff {
        /// Show only this tool (default: every tool that drifted).
        #[arg(long)]
        tool: Option<String>,
        #[command(flatten)]
        server: ServerArgs,
    },
    /// Accept the server's current tool definitions into the lockfile.
    Approve {
        /// Approve only this tool (default: all tools, dropping ones the server no longer has).
        #[arg(long)]
        tool: Option<String>,
        #[command(flatten)]
        server: ServerArgs,
    },
}

#[derive(Args)]
struct ServerArgs {
    /// Path to the lockfile.
    #[arg(long, default_value = "mcp.lock")]
    lock: PathBuf,
    /// The server command and its arguments.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    server: Vec<String>,
}

// Single-threaded runtime: the proxy is I/O bound and this keeps futures free of `Send` rules.
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<ExitCode> {
    // Logs go to stderr: in stdio mode stdout is the protocol channel.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    match Cli::parse().command {
        Cmd::Run(args) => {
            // A lockfile error doesn't stop the session: the interceptor hides every tool
            // (fail closed) and says why on stderr.
            let id = lockfile::server_id(&args.server);
            let lock = Lockfile::load(&args.lock)
                .map(|mut lock| lock.servers.remove(&id))
                .map_err(|e| e.to_string());
            let mut interceptor = Interceptor::new(lock, cli_args(&args));
            let mut transport = spawn(&args.server)?;
            mcp_lock::proxy::run(
                &mut transport,
                &mut interceptor,
                tokio::io::stdin(),
                tokio::io::stdout(),
            )
            .await?;
            // The server already had DRAIN_TIMEOUT to exit after the client left. If it still
            // hasn't, the timeout drops `transport`, and `kill_on_drop` stops the child.
            let Ok(status) = timeout(EXIT_TIMEOUT, transport.wait()).await else {
                tracing::warn!("server did not exit; killed it");
                return Ok(ExitCode::FAILURE);
            };
            // Propagate the server's exit code; 1 if it was killed by a signal.
            Ok(ExitCode::from(exit_byte(status?.code().unwrap_or(1))))
        }
        Cmd::Status(args) => status(args).await,
        Cmd::Diff { tool, server } => diff(server, tool.as_deref()).await,
        Cmd::Approve { tool, server } => approve(server, tool.as_deref()).await,
    }
}

async fn status(args: ServerArgs) -> anyhow::Result<ExitCode> {
    let lock = Lockfile::load(&args.lock)?;
    let (label, current) = snapshot(&args.server).await?;
    let id = lockfile::server_id(&args.server);
    let locked = lock.servers.get(&id);
    let verdicts = check(locked, &current);

    println!("{label} ({id})");
    if locked.is_none() {
        print_not_approved(&args);
    }
    for (name, verdict) in &verdicts {
        // Tool names and reasons come from the server: escape them before printing.
        let (tag, name) = (tag(verdict.severity), visible(name));
        if verdict.reasons.is_empty() {
            println!("  {tag:<6} {name}");
        } else {
            println!(
                "  {tag:<6} {name}: {}",
                visible(&verdict.reasons.join("; "))
            );
        }
    }
    // A server that was never approved is drift, even if it has no tools right now.
    Ok(exit_code(
        locked.is_some() && verdicts.values().all(|v| v.severity == Severity::None),
    ))
}

async fn diff(args: ServerArgs, only: Option<&str>) -> anyhow::Result<ExitCode> {
    let lock = Lockfile::load(&args.lock)?;
    let (_, current) = snapshot(&args.server).await?;
    let id = lockfile::server_id(&args.server);
    let locked = lock.servers.get(&id);
    let verdicts = check(locked, &current);

    let names: Vec<&String> = match only {
        Some(name) => match verdicts.get_key_value(name) {
            Some((name, _)) => vec![name],
            None => bail!("no tool named `{name}` on the server or in the lockfile"),
        },
        None => verdicts
            .iter()
            .filter(|(_, v)| v.severity != Severity::None)
            .map(|(name, _)| name)
            .collect(),
    };
    if locked.is_none() {
        print_not_approved(&args);
    } else if names.is_empty() {
        println!("no changes");
    }

    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    for name in &names {
        let verdict = &verdicts[*name];
        let old = locked
            .and_then(|s| s.tools.get(*name))
            .map(|t| &t.definition);
        let new = current.get(*name).map(|p| &p.definition);
        let header = if verdict.reasons.is_empty() {
            format!("{} [{}]", visible(name), tag(verdict.severity))
        } else {
            format!(
                "{} [{}: {}]",
                visible(name),
                tag(verdict.severity),
                visible(&verdict.reasons.join("; "))
            )
        };
        println!(
            "{}",
            if color {
                format!("\x1b[1m{header}\x1b[0m")
            } else {
                header
            }
        );
        print!("{}", mcp_lock::diff::render(old, new, color));
        println!();
    }
    Ok(exit_code(
        locked.is_some()
            && names
                .iter()
                .all(|n| verdicts[*n].severity == Severity::None),
    ))
}

fn print_not_approved(args: &ServerArgs) {
    println!(
        "  server is not in the lockfile; approve it with: mcp-lock approve {}",
        cli_args(args)
    );
}

/// The process exit code for a child's exit code. Exit codes are a byte on most systems,
/// so keep the low byte, but never let a failure (e.g. 256) wrap around to 0 = success.
fn exit_byte(code: i32) -> u8 {
    match (code & 0xff) as u8 {
        0 if code != 0 => 1,
        byte => byte,
    }
}

/// Short label for a severity, as shown by `status` and `diff`.
fn tag(severity: Severity) -> &'static str {
    match severity {
        Severity::None => "ok",
        Severity::Warn => "WARN",
        Severity::New => "NEW",
        Severity::Block => "BLOCK",
    }
}

/// `status` and `diff` exit 1 when anything drifted, so they can gate CI.
fn exit_code(clean: bool) -> ExitCode {
    if clean {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

async fn approve(args: ServerArgs, only: Option<&str>) -> anyhow::Result<ExitCode> {
    // Check first: if the lockfile is corrupt, refuse before even starting the server.
    Lockfile::load(&args.lock)?;
    let (label, current) = snapshot(&args.server).await?;
    let id = lockfile::server_id(&args.server);
    // Re-read just before writing: the server can take seconds to answer, and another
    // `approve` may have saved in the meantime. Saving a copy loaded earlier would drop it.
    // ponytail: a millisecond window remains between this load and the save; take a
    // `File::lock` on a sidecar file if concurrent approves ever need to be airtight.
    let mut lock = Lockfile::load(&args.lock)?;
    lock.approve(&id, &label, &current, only, &lockfile::now_utc())?;
    lock.save(&args.lock)?;
    let count = only.map_or(current.len(), |_| 1);
    eprintln!(
        "approved {count} tool(s) for {label} in {}",
        args.lock.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// Start the server, list its tools, shut it down. Returns (label, tool name -> pinned).
async fn snapshot(server: &[String]) -> anyhow::Result<(String, BTreeMap<String, Pinned>)> {
    let mut transport = spawn(server)?;
    let snap = timeout(LIST_TIMEOUT, mcp_lock::client::list_tools(&mut transport))
        .await
        .context("server did not list its tools in time")??;
    // If the server doesn't exit on its own, dropping the transport kills it.
    let _ = timeout(EXIT_TIMEOUT, transport.wait()).await;

    let pinned = fingerprint_tools(&snap.tools)?;
    // The label is server-supplied and gets printed: escape it once here.
    let label = visible(&snap.server_name.unwrap_or_else(|| server[0].clone()));
    Ok((label, pinned))
}

/// The arguments that identify this server to `mcp-lock`, for hints like
/// `mcp-lock diff --tool X <cli_args>`.
fn cli_args(args: &ServerArgs) -> String {
    format!(
        "--lock {} -- {}",
        args.lock.display(),
        args.server.join(" ")
    )
}

fn spawn(server: &[String]) -> anyhow::Result<StdioTransport> {
    let Some((program, args)) = server.split_first() else {
        bail!("missing server command");
    };
    StdioTransport::spawn(program, args).with_context(|| format!("failed to start `{program}`"))
}

#[cfg(test)]
mod tests {
    use super::exit_byte;

    #[test]
    fn nonzero_exit_codes_never_become_success() {
        // Issue #12.1: `256 as u8` is 0.
        assert_eq!(exit_byte(0), 0);
        assert_eq!(exit_byte(3), 3);
        assert_eq!(exit_byte(256), 1);
        assert_eq!(exit_byte(512 + 7), 7);
        assert_eq!(exit_byte(-1073741819), 5); // 0xC0000005 access violation on Windows
    }
}

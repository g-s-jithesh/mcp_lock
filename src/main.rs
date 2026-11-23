use anyhow::{bail, Context};
use clap::{Args, Parser, Subcommand};
use mcp_lock::classify::{check, check_instructions, visible, Severity, Verdict};
use mcp_lock::fingerprint::{fingerprint_tools, Pinned};
use mcp_lock::interceptor::Interceptor;
use mcp_lock::lockfile::{self, Lockfile, ServerEntry};
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
    /// Shows what will change and asks for confirmation; without a terminal it refuses
    /// unless --yes is given, so an agent can't approve tools on its own.
    Approve {
        /// Approve only this tool (default: all tools, dropping ones the server no longer has).
        #[arg(long)]
        tool: Option<String>,
        /// Approve without asking (for scripts and CI).
        #[arg(long)]
        yes: bool,
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
        Cmd::Approve { tool, yes, server } => approve(server, tool.as_deref(), yes).await,
    }
}

async fn status(args: ServerArgs) -> anyhow::Result<ExitCode> {
    let lock = Lockfile::load(&args.lock)?;
    let snap = snapshot(&args.server).await?;
    let id = lockfile::server_id(&args.server);
    let locked = lock.servers.get(&id);
    let verdicts = check(locked, &snap.tools);
    let instructions = check_instructions(locked, snap.instructions.as_deref());

    println!("{} ({id})", snap.label);
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
    if instructions.severity != Severity::None {
        println!(
            "  {:<6} (server instructions): {}",
            tag(instructions.severity),
            visible(&instructions.reasons.join("; "))
        );
    }
    // A server that was never approved is drift, even if it has no tools right now.
    Ok(exit_code(
        locked.is_some()
            && instructions.severity == Severity::None
            && verdicts.values().all(|v| v.severity == Severity::None),
    ))
}

async fn diff(args: ServerArgs, only: Option<&str>) -> anyhow::Result<ExitCode> {
    let lock = Lockfile::load(&args.lock)?;
    let snap = snapshot(&args.server).await?;
    let current = &snap.tools;
    let id = lockfile::server_id(&args.server);
    let locked = lock.servers.get(&id);
    let verdicts = check(locked, current);
    // Instructions are shown when diffing the whole server, not a single tool.
    let instructions = match only {
        Some(_) => None,
        None => Some(check_instructions(locked, snap.instructions.as_deref()))
            .filter(|v| v.severity != Severity::None),
    };

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
    } else if names.is_empty() && instructions.is_none() {
        println!("no changes");
    }

    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    if let Some(verdict) = &instructions {
        print_header("(server instructions)", verdict, color);
        let as_field = |text: &str| serde_json::json!({ "instructions": text });
        let old = locked.and_then(|e| e.instructions.as_deref()).map(as_field);
        let new = snap.instructions.as_deref().map(as_field);
        print!(
            "{}",
            mcp_lock::diff::render(old.as_ref(), new.as_ref(), color)
        );
        println!();
    }
    for name in &names {
        let verdict = &verdicts[*name];
        let old = locked
            .and_then(|s| s.tools.get(*name))
            .map(|t| &t.definition);
        let new = current.get(*name).map(|p| &p.definition);
        print_header(&visible(name), verdict, color);
        print!("{}", mcp_lock::diff::render(old, new, color));
        println!();
    }
    Ok(exit_code(
        locked.is_some()
            && instructions.is_none()
            && names
                .iter()
                .all(|n| verdicts[*n].severity == Severity::None),
    ))
}

/// `name [TAG: reasons]`, bold when colour is on. `name` must already be escaped.
fn print_header(name: &str, verdict: &Verdict, color: bool) {
    let header = if verdict.reasons.is_empty() {
        format!("{name} [{}]", tag(verdict.severity))
    } else {
        format!(
            "{name} [{}: {}]",
            tag(verdict.severity),
            visible(&verdict.reasons.join("; "))
        )
    };
    if color {
        println!("\x1b[1m{header}\x1b[0m");
    } else {
        println!("{header}");
    }
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

async fn approve(args: ServerArgs, only: Option<&str>, yes: bool) -> anyhow::Result<ExitCode> {
    // Check first: if the lockfile is corrupt, refuse before even starting the server.
    let before = Lockfile::load(&args.lock)?;
    let snap = snapshot(&args.server).await?;
    let id = lockfile::server_id(&args.server);

    let changes = pending_changes(before.servers.get(&id), &snap, only);
    if !changes.is_empty() && !yes && !confirm(&snap.label, &changes, &args)? {
        eprintln!("not approved; mcp.lock is unchanged");
        return Ok(ExitCode::FAILURE);
    }
    // Re-read just before writing: the server can take seconds to answer, and another
    // `approve` may have saved in the meantime. Saving a copy loaded earlier would drop it.
    // ponytail: a millisecond window remains between this load and the save; take a
    // `File::lock` on a sidecar file if concurrent approves ever need to be airtight.
    let mut lock = Lockfile::load(&args.lock)?;
    lock.approve(&id, &snap.label, &snap.tools, only, &lockfile::now_utc())?;
    // Approving one tool leaves the server's instructions as they were approved before.
    if only.is_none() {
        lock.approve_instructions(&id, snap.instructions.as_deref());
    }
    lock.save(&args.lock)?;
    let count = only.map_or(snap.tools.len(), |_| 1);
    let and_instructions = if only.is_none() && snap.instructions.is_some() {
        " and the server's instructions"
    } else {
        ""
    };
    eprintln!(
        "approved {count} tool(s){and_instructions} for {} in {}",
        snap.label,
        args.lock.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// What approving would change, one line per tool (or the server's instructions), in the
/// same form `status` prints. Empty when the server is already approved as it is.
fn pending_changes(locked: Option<&ServerEntry>, snap: &Snap, only: Option<&str>) -> Vec<String> {
    let line = |name: &str, verdict: &Verdict| {
        format!(
            "  {:<6} {name}: {}",
            tag(verdict.severity),
            visible(&verdict.reasons.join("; "))
        )
    };
    let mut lines: Vec<String> = check(locked, &snap.tools)
        .iter()
        .filter(|(name, v)| v.severity != Severity::None && only.is_none_or(|o| o == *name))
        .map(|(name, v)| line(&visible(name), v))
        .collect();
    let instructions = check_instructions(locked, snap.instructions.as_deref());
    if only.is_none() && instructions.severity != Severity::None {
        lines.push(line("(server instructions)", &instructions));
    }
    lines
}

/// Ask the person at the terminal to confirm. Without a terminal (an agent's shell, a script),
/// refuse: approving is the one step a person must take, and `--yes` makes it explicit.
fn confirm(label: &str, changes: &[String], args: &ServerArgs) -> anyhow::Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "refusing to approve without confirmation: no terminal to ask in.\n\
             Review with `mcp-lock diff {}`, then run approve in a terminal, \
             or pass --yes (for scripts and CI).\n\
             If you are an AI agent: ask the user to review and approve; don't pass --yes yourself.",
            cli_args(args)
        );
    }
    eprintln!("Approving will accept these changes for {label}:");
    for change in changes {
        eprintln!("{change}");
    }
    eprint!("Approve? [y/N] ");
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes" | "YES"))
}

/// What `snapshot()` learned from a server.
struct Snap {
    /// `serverInfo.name` (or the command), escaped for printing.
    label: String,
    /// Tool name -> fingerprint and canonical definition.
    tools: BTreeMap<String, Pinned>,
    /// The server's `instructions` from `initialize`, if any.
    instructions: Option<String>,
}

/// Start the server, list its tools, shut it down.
async fn snapshot(server: &[String]) -> anyhow::Result<Snap> {
    let mut transport = spawn(server)?;
    let snap = timeout(LIST_TIMEOUT, mcp_lock::client::list_tools(&mut transport))
        .await
        .context("server did not list its tools in time")??;
    // If the server doesn't exit on its own, dropping the transport kills it.
    let _ = timeout(EXIT_TIMEOUT, transport.wait()).await;

    let tools = fingerprint_tools(&snap.tools)?;
    // The label is server-supplied and gets printed: escape it once here.
    let label = visible(&snap.server_name.unwrap_or_else(|| server[0].clone()));
    Ok(Snap {
        label,
        tools,
        instructions: snap.instructions,
    })
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

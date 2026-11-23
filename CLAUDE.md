# CLAUDE.md — mcp.lock

Guidance for Claude Code (and any coding agent) working in this repository.

## What this project is

`mcp-lock` is a small Rust proxy that sits between an MCP client (Claude Code, Cursor, etc.)
and an MCP server. The first time you approve a server, it records a fingerprint of every
tool's definition (name, description, input schema, annotations) in `mcp.lock`. On every later
session, it compares what the server advertises against the lockfile. If a tool definition has
changed in a way that could change agent behaviour ("rug pull" / tool poisoning), the proxy
hides that tool and blocks calls to it until the user re-approves it.

Think of it as `package-lock.json` for agent tools.

### Prior art (be honest about it)
Tool pinning already exists in mcp-scan (Invariant), toolprint, RugSnare, aiguard-scanner-mcp
and cc-audit. Do **not** describe this project as "the first" anywhere (README, docs, commits).
Our focus, and the thing worth getting right:
1. **Canonicalization + severity classification**: fewer false alarms than raw hashing, while
   still catching real attacks.
2. **A measurable benchmark**: detection rate vs false-alarm rate against an attack corpus.
3. **Clean Rust architecture**: transport-agnostic interceptor, single binary.

## Tech stack

- Rust, stable toolchain, edition 2021. Single binary crate + library (`src/lib.rs`) so logic is testable.
- Async: `tokio`. JSON: `serde`, `serde_json`. Hashing: `sha2`. CLI: `clap` (derive).
- Errors: `thiserror` in the library, `anyhow` in `main.rs` only.
- Diffs: `similar`. Logging: `tracing` + `tracing-subscriber`.
- Do not add other dependencies without stating why in the PR/commit message.

## Commands

```bash
cargo build                      # build
cargo test                       # all tests (must pass before any commit)
cargo clippy -- -D warnings      # lints are errors
cargo fmt --check                # formatting
cargo run -- run -- <server cmd> # run the proxy in front of a stdio MCP server
```

Run `cargo fmt && cargo clippy -- -D warnings && cargo test` before declaring any task done.

## CLI surface (target)

```
mcp-lock run [--lock mcp.lock] -- <server command> [args...]   # proxy mode (stdio)
mcp-lock status [--lock mcp.lock] -- <server command>          # show drift, change nothing
mcp-lock approve [--tool <name>] -- <server command>           # accept current definitions
mcp-lock diff --tool <name> -- <server command>                # human-readable diff
```

Client config example (what users put in their MCP config):
```json
{ "command": "mcp-lock", "args": ["run", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."] }
```

## Architecture

```
src/
  main.rs            # CLI parsing only; calls into lib
  lib.rs
  transport/
    mod.rs           # `Transport` trait; bounded line reader/writer shared by both sides
    stdio.rs         # spawn child process, newline-delimited JSON-RPC over stdin/stdout
    http.rs          # (later) Streamable HTTP
  proxy.rs           # pumps client <-> server, asking the interceptor about each message
  interceptor.rs     # inspects JSON-RPC messages; transport-agnostic
  client.rs          # minimal MCP client used by approve/status/diff (lists tools only)
  canonical.rs       # normalize tool definitions before hashing
  fingerprint.rs     # SHA-256 over canonical form
  classify.rs        # compare old vs new definition -> Severity
  diff.rs            # human-readable field-by-field diff for `mcp-lock diff`
  lockfile.rs        # read/write mcp.lock (atomic writes)
tests/
  fixtures/          # recorded tools/list responses + attack/benign corpus
examples/
  benchmark.rs       # detection vs false-alarm rates per policy
```

The policy is a single method for now, `Severity::hides()`. A separate `policy.rs` was planned
but not needed; add it when there is more than one policy to choose at runtime.

### Hard rules

1. **The interceptor never knows about the transport.** It receives and returns
   `serde_json::Value` JSON-RPC messages. Stdio first; HTTP/SSE must slot in by implementing
   the `Transport` trait, with no changes to `interceptor.rs`.
2. **stdout is the protocol channel in stdio mode.** Never `println!`. All logs go to stderr
   via `tracing`. A stray print corrupts the session.
3. **Pass through everything we don't understand**, unchanged and in order. We only act on:
   - `initialize` responses (remove server `instructions` that don't match the lock: clients
     put them in the model's prompt, so a server could rug-pull through them while keeping
     every tool identical. Added 2026-11-24.)
   - `tools/list` responses (compare against lock; strip unapproved/changed tools)
   - `tools/call` requests (reject calls to blocked tools with a JSON-RPC error; do not forward)
   - `notifications/tools/list_changed` (forward, then re-check on the next `tools/list`)
4. **Fail closed on our own errors for tool definitions**, fail open never. If the lockfile is
   unreadable, block tools rather than silently allowing them, and say why on stderr.
5. **Lockfile writes are atomic** (write temp file, then rename). Never partially write `mcp.lock`.
6. The proxy must not call tools, modify arguments, or touch the network on its own.

### Canonicalization (canonical.rs)

Hash a normalized form, not raw bytes:
- Sort object keys recursively (RFC 8785 / JCS style); keep array order **except** for
  sets where order has no meaning (`required`, `enum`): sort those.
- Normalize Unicode to NFC and line endings to `\n`. Do **not** trim or collapse whitespace
  inside `description`: hidden instructions can live in whitespace and zero-width chars.
  Flag zero-width / bidi control characters explicitly as a finding.
- Keep `annotations` (e.g. `readOnlyHint`, `destructiveHint`) in the hash: flipping them matters.

### Severity (classify.rs)

| Change | Severity | Default action |
|---|---|---|
| Key reorder, formatting only | None | Silent |
| Empty `required` / `properties` / `annotations` added or removed (same meaning as absent) | Warn | Allow, log on stderr |
| New optional parameter that is purely structural (identifier name ≤ 32 chars; only `type`, numeric/length/item bounds, boolean `additionalProperties`/`uniqueItems`, structural `items`) | Warn | Allow, log on stderr |
| Any other new optional parameter (description, enum, const, pattern, format, nested properties, vendor keys, sentence-like name, …) | Block | Hide + reject calls |
| New tool not in lock | New | Hidden until approved |
| Description text changed | Block | Hide + reject calls |
| Constraint removed/loosened (`required`, `enum`, `maxLength`, `pattern`, type widened) | Block | Hide + reject calls |
| New required parameter | Block | Hide + reject calls |
| Annotation changed | Block | Hide + reject calls |
| Tool removed | Warn | Log |
| Server `instructions` added or changed | Block | Remove them from the `initialize` response |
| Server `instructions` removed | Warn | Log |
| Zero-width / bidi control chars added | Block | Hide + reject calls |

When unsure how to classify a change, choose **Block** and add a test case documenting it.

Why text-carrying optional parameters block: the model reads parameter descriptions, so they
can carry instructions (benchmark case `a18`). Warning on them missed that attack; blocking
costs one extra false alarm on the benchmark (`b09`). Decided 2026-11-19 from benchmark data.

### Lockfile format (mcp.lock)

JSON, pretty-printed, sorted keys, committed to git so changes show up in code review.

```json
{
  "version": 1,
  "servers": {
    "<server id: hash of command + args, or URL>": {
      "label": "server-filesystem",
      "instructions": "…normalized server instructions, if the server sends any…",
      "tools": {
        "read_file": {
          "hash": "sha256:…",
          "approved_at": "2026-11-19T10:00:00Z",
          "definition": { "...canonical definition, stored so diffs are possible..." }
        }
      }
    }
  }
}
```

Store the full canonical definition, not only the hash: without it we can't show a diff.

## Testing

- Every `classify.rs` rule needs a unit test with a before/after fixture.
- `tests/fixtures/attacks/`: one benign definition + its poisoned twin per file. Every attack
  must be detected; every benign-only change must produce no Block.
- Integration test: spawn a fake MCP server (a tiny Rust or Python script in `tests/`) that
  changes a tool description between two runs; assert the second run blocks it.
- Proxy transparency test: for a session with no drift, client sees byte-for-byte identical
  JSON-RPC messages (modulo whitespace) compared with talking to the server directly.

## Quest board

| # | Quest | Done when |
|---|---|---|
| 1 | Transparent stdio pipe | Works with a real filesystem MCP server in Claude Code; transparency test passes |
| 2 | Canonicalize + fingerprint | `tools/list` hashed; key reorder produces same hash (test) |
| 3 | Lockfile + approve flow | `approve`, `status`, atomic writes; lock round-trips |
| 4 | Classify + enforce | Severity table implemented; blocked tool hidden and calls rejected with JSON-RPC error |
| 5 | Diff UX | `mcp-lock diff` prints a readable coloured diff of the changed field |
| 6 | Benchmark | Attack corpus + script reports detection rate and false alarms per policy |
| 7 | Ship | README with demo GIF, CI (fmt, clippy, test), `cargo install` works |
| 8 | (later) HTTP transport | Streamable HTTP implemented via `Transport` trait only |

Work one quest at a time. Don't start the next quest until the current one's "done when" holds.

## Working style for agents

- Plan before coding: for any non-trivial change, state the files you'll touch and the test
  you'll add first.
- Small commits, one logical change each. Conventional commit prefixes (`feat:`, `fix:`,
  `test:`, `refactor:`, `docs:`).
- This project will run past 5 commits: for big quests, split work across subagents:
  one implements, one writes tests/fixtures, one reviews the diff against the hard rules above.
  The orchestrating agent verifies by running the full check command before merging.
- No `unwrap()`/`expect()` outside tests and `main.rs` startup. No `unsafe`.
- Keep functions small; public items in `lib.rs` get doc comments.
- If a requirement here conflicts with the MCP spec, the spec wins: note it here and in the PR.

## Owner context

Built by a final-year student learning Rust. Prefer clear, idiomatic code over clever code,
and explain non-obvious Rust (lifetimes, trait objects, async boundaries) in short comments.

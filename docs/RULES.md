# The Weld Rules Book

A complete reference for the weld rules language — the policy DSL that
describes what an AI agent may and may not do. Every rule compiles into a
deterministic finite-state machine (the *supervisor*) that sits between the
agent and the world.

> **Design principle.** Unsafe actions become *unreachable*, not discouraged.
> A prompt can be ignored; a compiled supervisor cannot.

---

## Table of contents

1. [The mental model](#the-mental-model)
2. [Events](#events)
3. [Statements](#statements)
   - [`set` — named glob sets](#set--named-glob-sets)
   - [`observe` — unenforceable events](#observe--unenforceable-events)
   - [`control` — enforceable events](#control--enforceable-events)
   - [`state` — latches](#state--latches)
   - [`deny` — single-event and trace rules](#deny--single-event-and-trace-rules)
   - [`mark` — goal states](#mark--goal-states)
4. [Guards and expressions](#guards-and-expressions)
5. [Pattern matching (`~`) and alternation](#pattern-matching--and-alternation)
6. [The trace operator `~>`](#the-trace-operator-)
7. [The count latch and its off-by-one](#the-count-latch-and-its-off-by-one)
8. [Path canonicalization](#path-canonicalization)
9. [Tool coverage — what MCP tools map to what events](#tool-coverage)
10. [Gotchas](#gotchas)
11. [Cookbook — recipes for real agent risks](#cookbook)
12. [Toolchain reference](#toolchain-reference)

---

## The mental model

Weld treats an agent session as a sequence of discrete **events**. A rules
file describes:

- which events exist (`observe` / `control`),
- what the agent has done so far (**latches** and monitor positions),
- and which sequences of events must never complete (**deny rules**).

At startup, weld synthesizes a **supervisor** — a finite-state machine whose
states are the safe configurations of "what has happened so far". Every
incoming tool call or command is checked against the FSM *before* it runs:

- If the action keeps the agent within the safe region, it is **allowed**.
- If the action would leave the safe region (complete a forbidden trace,
  violate a guard, enter a forbidden state), it is **denied** before it
  executes.

Denial is returned to the agent as a structured error carrying the rule and
a plain-language reason, so an LLM agent can *replan* instead of retrying
blindly.

---

## Events

An event is the atomic unit of supervision. It has a name and zero or more
arguments.

| Event | Meaning | Typical source |
|---|---|---|
| `exec` | A shell command or program invocation | `bash` tool, `weld shim` |
| `fs.read` | Reading a file or directory | `read_file`, `glob`, `grep`, `list_directory` |
| `fs.write` | Creating or modifying a file | `write_file`, `edit_file`, `create_directory` |
| `fs.delete` | Removing a file | `delete_file`, derived from `rm` |
| `fs.move` | Renaming/moving a file (two path args) | `move_file`, `rename`, derived from `mv` |
| `fs.chmod` | Changing permissions | `chmod`, `chown` (derived) |
| `net.connect` | Opening a network connection (host arg) | `fetch`, `webfetch` |
| `net.recv` | Receiving network data | — |
| `vcs.push` | Pushing to a remote | `git_push` |
| `vcs.force_push` | Force-pushing (rewriting history) | `git_force_push` |
| `vcs.branch_delete` | Deleting a branch | `git_delete_branch` |
| `vcs.commit` | Committing | `git_commit` |
| `db.query` | Querying a database | `sql`, `query_database` |
| `db.drop` | Dropping a database object | — |
| `backup.create` | Creating a backup | — |
| `backup.delete` | Deleting a backup | — |
| `proc.exit` | A process exiting | — |
| `mcp.tool` | An MCP tool invocation (tool name, server name) | `weld run --name <server>` |
| `llm.call` | An LLM invocation (model identifier) | `weld shim`, derived from agent CLIs |
| `agent.spawn` | A nested agent invocation | `weld shim`, derived from agent CLIs |

Event names are hierarchical with `.`; a rule may use a prefix wildcard:

- `vcs.*` — matches `vcs.push`, `vcs.force_push`, `vcs.branch_delete`, …

---

## Statements

A rules file is a sequence of statements, one per line. Comments start with
`#` and run to end of line.

### `set` — named glob sets

```weld
set secrets = **/.env* **/*.pem **/id_rsa*
```

A named set is a collection of glob patterns. Sets are used in guards via
`in` / `not in`. Patterns are matched against the *canonicalized* argument
(see [Path canonicalization](#path-canonicalization)), so:

- `~/...` patterns expand to the user's home directory,
- `./...` patterns are anchored to the directory weld runs in,
- `**` crosses directory boundaries.

### `observe` — unenforceable events

```weld
observe fs.read net.recv proc.exit
```

Observed events are *recorded in the audit log* and may participate in
guards and trace rules, but weld cannot prevent them (you cannot stop an
agent from reading a file it already opened, for example). Observed events
can never appear as the final condition of a deny rule — `weld check`
rejects that.

### `control` — enforceable events

```weld
control fs.write fs.delete exec net.connect vcs.*
```

Controlled events are the ones weld can actually gate: the action is
intercepted *before* it happens, and a deny decision prevents it from
executing at all.

### `state` — latches

A latch is one bit of memory about the session's history.

```weld
state tainted = seen fs.read(p) if p in secrets
state green   = last exec("cargo test") == 0
state clean   = last exec("git status --porcelain") == ""
state snapped = seen backup.create(_)
state hot      = count fs.delete(_) since exec("cargo test") > 50
```

Three kinds:

| Kind | Meaning | Guard comparison |
|---|---|---|
| `seen` | The event has occurred at least once since the start (or since the `since` event) | optional `== / != / < / >` against a count literal |
| `last` | The most recent occurrence of the event had the given result | `==`, `!=`, `<`, `>`, `<=`, `>=` against a string or number |
| `count` | The number of occurrences since the `since` event | numeric comparison against an integer literal (0…10 000) |

Latches are referenced in guards by name (`tainted`, `green`, …) and can be
combined with boolean operators.

### `deny` — single-event and trace rules

A deny rule has one or more conditions. A single-condition rule fires when
the event happens and its guard holds:

```weld
deny fs.write(p) if p in secrets
```

A multi-condition rule is a **trace**: it fires when the sequence happens in
order (not necessarily consecutively):

```weld
deny backup.delete(_) ~> db.drop(_)
```

See [The trace operator](#the-trace-operator-) for details.

### `mark` — goal states

```weld
mark done if green and clean
```

Marks declare *goal states* of the session. The supervisor's safety check
(co-reachability pruning) uses marks: any state from which no marked state
is reachable is *unsafe* and is disabled. In practice this lets you express
"the agent must pass through validation before shipping" style policies.

---

## Guards and expressions

A guard is an expression after `if`. Guard variables are bound from the
event's arguments (`deny fs.write(p) if p in secrets` binds `p` to the path
being written).

| Expression | Meaning |
|---|---|
| `p in secrets` | the value of `p` matches the set `secrets` |
| `p not in secrets` | negation |
| `c ~ "curl *"` | the value of `c` matches the glob pattern |
| `c !~ "curl *"` | negated match (also `not (c ~ "...")`) |
| `env("ENV") == "production"` | environment variable comparison |
| `a and b`, `a or b`, `not a` | boolean composition |

Comparisons: `==`, `!=`, `<`, `>`, `<=`, `>=`.

---

## Pattern matching (`~`) and alternation

The `~` operator uses weld's minimal glob matcher:

- `*` matches any sequence of characters (including spaces and `/`)
- `?` matches exactly one character
- `|` separates **alternatives** — the guard holds if *any* alternative
  matches

```weld
deny exec(c) if c ~ "curl *|wget *|nc *"
```

This is one clause covering three commands. Alternatives are tried in order
and the guard holds if any of them matches the whole string.

> Note the difference from `set` patterns: `set` uses the globset engine
> (brace expansion, character classes, directory-aware `**` semantics),
> while `~` uses the minimal matcher above. `set` patterns are anchored
> (`~/...` to home, `./...` to the working directory); `~` patterns match
> the raw string.

---

## The trace operator `~>`

`~>` reads as "eventually followed by". A trace rule

```weld
deny backup.delete(_) ~> db.drop(_)
```

fires when `db.drop` happens at any point *after* a `backup.delete` has been
observed. Between the two events, any number of unrelated events may occur.

Key properties:

- **Non-consecutive.** The two events need not be adjacent in the event
  stream.
- **Positional monitors.** Each rule keeps a monitor position per state;
  matching a non-final condition advances the monitor without denying.
- **Reset on completion.** After a trace fires (or completes), the monitor
  resets so a second violation is detected independently.
- **Guarded steps.** Each step may carry its own guard:

  ```weld
  deny fs.read(p) if p in secrets ~> vcs.commit(_)
  ```

  Here only reads of secret files arm the rule.

---

## The count latch and its off-by-one

Because guards are evaluated *before* the event is applied, a rule like

```weld
deny fs.delete(_) if count fs.delete since exec("cargo test") > 50
```

blocks the **52nd** delete, not the 51st: the 51st delete sees the counter
at 50, the guard `> 50` is false, the delete is allowed and the counter
becomes 51; the 52nd delete sees 51, the guard fires.

**Rule of thumb:** with `count … > N`, the first N+1 occurrences pass and
occurrence N+2 is blocked. If you want "at most N", write `>= N+1`… and
test it with `weld replay`.

---

## Path canonicalization

Before any guard evaluation, path arguments of `fs.*` events are
canonicalized:

1. `~` / `~/...` expands to the user's home directory,
2. relative paths are resolved against the current working directory,
3. `.` and `..` components are resolved lexically (no filesystem access),
   so `src/../../etc/passwd` cannot smuggle past a prefix rule.

Set patterns participate in the same convention: `~/...` expands to home,
`./...` is anchored to the working directory, and both the raw and the
anchored form are registered so offline replays still match.

---

## Tool coverage

The MCP proxy maps tool names to events. Mapping is case-insensitive and
supports common aliases from popular agent frameworks:

| Tools | Event |
|---|---|
| `bash`, `shell`, `execute_command`, `run_command`, `terminal`, `run_terminal_cmd` | `exec` |
| `write_file`, `create_file`, `edit_file`, `create_directory`, `Write`, `Edit`, `MultiEdit` | `fs.write` |
| `notebook_edit`, `NotebookEdit` | `fs.write` |
| `read_file`, `read_text_file`, `read_media_file`, `read_multiple_files`, `Read`, `get_file` | `fs.read` |
| `list_directory`, `directory_tree`, `search_files`, `get_file_info`, `list_allowed_directories`, `glob`, `grep`, `list` | `fs.read` (observed-style) |
| `delete_file`, `remove_file` | `fs.delete` |
| `move_file`, `rename` | `fs.move` |
| `http_request`, `fetch`, `web_fetch`, `webfetch`, `web_search`, `open_url` | `net.connect` |
| `git_push` | `vcs.push` |
| `git_force_push` | `vcs.force_push` |
| `git_delete_branch` | `vcs.branch_delete` |
| `git_commit`, `commit` | `vcs.commit` |
| `sql`, `query_database`, `execute_sql` | `db.query` |

Anything not in the table is **unknown** and fails closed with an error
explaining why. Stateless scratch-pad tools (`todo_write`, `todowrite`,
`think`) are forwarded without policy evaluation but still audit-logged.

### MCP and agentic-AI supervision

Modern agents are not single models — they call MCP servers, spawn
sub-agents, and invoke LLMs directly. Weld models each of these as a
first-class event so policies can reason about the whole agent hierarchy,
not just the filesystem.

#### `mcp.tool` — server-level gating

Every `tools/call` request also produces an `mcp.tool` event whose
arguments are the tool name and the *server name* (from `weld run
--name <server>`). This lets a policy deny entire servers, or individual
tools on a specific server, independent of the per-tool event mapping:

```weld
set mcp_servers = fs sh
deny mcp.tool(n, s) if s not in mcp_servers
```

The `mcp.tool` check runs *before* the per-tool event check, so a denied
server blocks all of its tools even if the mapped event itself would be
allowed. `mcp.tool` rules evaluate *in addition to* the mapped event's
rules — they never widen what is allowed.

#### `agent.spawn` and `llm.call` — nested agent supervision

When a shell command invokes a known agent CLI (see `AGENT_CLIS` in
`mapping.rs`), weld derives two additional events:

- `agent.spawn(cli)` — a nested agent is being launched;
- `llm.call(model)` — the model it would drive (`--model X` / `-m X`,
  or the CLI name when no model flag is present).

These are checked in addition to `exec`, so policies can deny nested
agents entirely, cap how many are spawned, or forbid spawning agents
after the session has touched secrets:

```weld
deny fs.read(p) if p in secrets ~> agent.spawn(_)
```

Derived events never *widen* what is allowed — they only add checks on
top of the `exec` verdict.

---

## Gotchas

1. **`~` patterns have no `|` alternation** — *this changed.* Alternation is
   now supported: `c ~ "curl *|wget *"`. Older rule files need no change;
   the feature is additive. (Note: `|` inside a `set` pattern is *not*
   special — sets already accept multiple whitespace-separated patterns.)
2. **You can't deny an observe event.** The final condition of a deny rule
   must be controllable; `weld check` rejects the file otherwise.
3. **`count … > N` blocks the N+2-th occurrence**, because the guard is
   evaluated before the event is applied. See
   [the count latch](#the-count-latch-and-its-off-by-one).
4. **`last` is session-scoped.** If the event never ran, `last exec("cargo
   test") == 0` is false — which is usually what you want for "must have
   passed tests before pushing".
5. **Trace rules are not scoped to tool sessions.** Once the first step
   matches, the monitor stays armed until the trace completes or resets.
   A denied event does *not* advance a monitor — denials never count as
   occurrences.
6. **Symlinks are followed lexically, not physically.** `..` is resolved in
   the string; a symlink pointing outside the project is not detected.
   Keep sacred paths (like `.git/**`) in the sets rather than relying on
   path containment alone.

---

## Cookbook

### 1. Protect the prompt (SKILL.md / AGENTS.md) from the agent itself

```weld
set sacred = ./SKILL.md ./AGENTS.md ./.git/**
deny fs.write(p) if p in sacred
deny fs.delete(p) if p in sacred
deny fs.move(p, q) if p in sacred
```

The LLM may not rewrite the very instructions it follows — closing the
prompt-injection self-modification loop.

### 2. The exfiltration latch (read a secret ⇒ no network)

```weld
set secrets = **/.env* **/*.pem **/id_rsa*
state tainted = seen fs.read(p) if p in secrets
deny net.connect(h) if h not in hosts or tainted
```

Reading a secret permanently taints the session: afterwards, only
allowlisted hosts are reachable. This closes the classic
*read-then-exfiltrate* pattern that per-call allowlists cannot express.

### 3. Delete-then-drop (backups must survive database destruction)

```weld
deny backup.delete(_) ~> db.drop(_)
```

If the agent deletes a backup and then drops the database, the *sequence*
is denied — even though each individual action looked harmless.

### 4. No history rewriting without a snapshot

```weld
state snapped = seen backup.create(_)
deny exec(c) if c ~ "git reset --hard *" and not snapped
deny vcs.force_push(b) if b in locked
```

### 5. Rate-limit destructive operations

```weld
deny fs.delete(_) if count fs.delete since exec("cargo test") > 50
```

A test run resets the counter; a runaway agent that starts deleting files
en masse hits the ceiling.

### 6. Branch protection

```weld
set locked = main release/*
deny vcs.force_push(b) if b in locked
deny vcs.branch_delete(b) if b in locked
deny vcs.push(b) if b in locked and not green
state green = last exec("cargo test") == 0
```

Pushes to `main` require a green test run in the same session.

### 7. Blocking shell workarounds for denied tools

```weld
deny exec(c) if c ~ "curl *" or c ~ "wget *" or c ~ "nc *"
```

With alternation, one clause covers the download tool family.

### 8. Environment-gated policy

```weld
deny db.query(_) if env("ENV") == "production"
```

---

## Toolchain reference

| Command | What it does |
|---|---|
| `weld init --preset solo-dev` | Scaffold `weld.rules` from a preset (`solo-dev`, `ci`, `paranoid`) |
| `weld check` | Compile rules, synthesize the supervisor, print a report (rules, states, events disabled at start) |
| `weld check --dot out.dot` | Additionally write the supervisor FSM as a Graphviz DOT graph |
| `weld run -- <mcp-server>` | Run the MCP stdio proxy in front of a server |
| `weld shim -- <command>` | Run a single command under supervision (exit 126 on deny) |
| `weld why <id>` | Explain a rule in plain language |
| `weld verify` | Verify the audit log's hash chain |
| `weld replay --rules new.rules` | Replay the audit log against new rules (what-if analysis) |

### Reading the DOT output

- **Solid ellipse** — a safe (kept) state.
- **Dashed, rose-filled ellipse** — a pruned/unsafe state; the supervisor
  will deny any event that would enter it.
- **Double ellipse** — a marked (goal) state.
- **Red self-loop** — a tool call that would complete a deny rule from this
  state (labeled with the rule id).
- **`start` arrow** — the initial state.

Node labels show the monitor position per rule (`r2@1` = rule 2 has matched
its first condition) and the latch values (`tainted=1`, `green=0`,
`count=3`).

### Interpreting "disabled at start"

If `weld check` lists events disabled at the initial state, those actions
are denied from the very beginning of every session — often a sign that a
latch starts in the wrong configuration (e.g. a `last` latch whose guard is
false until the event runs, combined with a deny that requires it). Review
those rules before deploying.

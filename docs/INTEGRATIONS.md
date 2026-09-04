# Weld Integration Guide

Weld works with **any MCP-compatible client**. This guide covers the
three most common setups — Claude Desktop, Claude Code, and OpenAI Codex
CLI — plus general patterns for other clients.

---

## 1. Claude Desktop

Claude Desktop supports stdio MCP servers via its config file.

### Step 1: Locate the config file

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

### Step 2: Add a weld-proxied server

```json
{
  "mcpServers": {
    "weld-fs": {
      "command": "/Users/YOURNAME/.cargo/bin/weld",
      "args": [
        "run",
        "--name", "fs",
        "--rules", "/Users/YOURNAME/projects/myapp/weld.rules",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem",
        "/Users/YOURNAME/projects/myapp"
      ]
    },
    "weld-sh": {
      "command": "/Users/YOURNAME/.cargo/bin/weld",
      "args": [
        "run", "--name", "sh",
        "--rules", "/Users/YOURNAME/projects/myapp/weld.rules",
        "--", "weld", "mcp-shell"
      ]
    }
  }
}
```

**Notes:**
- Use **absolute paths** for both `--rules` and the server command — Claude
  Desktop does not inherit your shell's working directory.
- Restart Claude Desktop after editing the config.

### Step 3: Verify

Open Claude Desktop and check the tools panel. Tools whose mapped event
would be denied at the initial state are **filtered out of the tool list
entirely** — the agent never sees them. Remaining tools are enforced
per-call.

---

## 2. Claude Code

Claude Code can run weld-wrapped MCP servers via `claude mcp add`.

### Add a filesystem server

```bash
claude mcp add weld-fs -- \
  weld run --name fs --rules "$PWD/weld.rules" -- \
  npx -y @modelcontextprotocol/server-filesystem .
```

### Add a shell server

```bash
claude mcp add weld-sh -- \
  weld run --name sh --rules "$PWD/weld.rules" -- \
  node mcp-shell.mjs
```

Use absolute paths for `--rules` if you'll run `claude` from other
directories. Scope to the current session with `--scope session` if
preferred.

### Verifying it's active

```bash
claude mcp list
```

You should see `weld-fs` and/or `weld-sh` with a green checkmark.

---

## 3. OpenAI Codex CLI

Codex CLI supports MCP servers via its TOML config file at
`~/.codex/config.toml`.

### Step 1: Install Codex (if needed)

```bash
npm install -g @openai/codex
```

### Step 2: Configure

Add a `[mcp_servers.weld]` section to `~/.codex/config.toml`:

```toml
[mcp_servers.weld-fs]
command = "/Users/YOURNAME/.cargo/bin/weld"
args = [
  "run",
  "--name", "fs",
  "--rules", "/Users/YOURNAME/projects/myapp/weld.rules",
  "--",
  "npx", "-y", "@modelcontextprotocol/server-filesystem",
  "/Users/YOURNAME/projects/myapp"
]

[mcp_servers.weld-sh]
command = "/Users/YOURNAME/.cargo/bin/weld"
args = [
  "run", "--name", "sh",
  "--rules", "/Users/YOURNAME/projects/myapp/weld.rules",
  "--", "node", "mcp-shell.mjs"
]
```

### Step 3: Verify

```bash
codex mcp list
```

Weld's supervision applies to every tool call Codex makes through the
proxied server.

---

## 4. OpenAI ChatGPT (Desktop / Connectors)

ChatGPT desktop and ChatGPT connectors support remote MCP servers (HTTP +
SSE). Weld currently exposes **stdio** servers only, so direct ChatGPT
integration requires a stdio-to-HTTP bridge.

### Option A: Use `mcp-remote` as a bridge

```bash
npx -y mcp-remote-proxy weld -- stdio-command
```

### Option B: Use a local stdio-to-SSE shim

```bash
npx -y mcp-proxy --port 8080 -- \
  weld run --name fs --rules ./weld.rules -- \
  npx -y @modelcontextprotocol/server-filesystem .
```

Then point ChatGPT at `http://localhost:8080/sse`.

> **Note:** Direct stdio support for ChatGPT is on the roadmap. For now,
> a bridge is required.

---

## 5. Other MCP clients (Cursor, Windsurf, Zed, …)

Most MCP clients follow the same pattern: a JSON config with a `command`
and `args` array.

### Cursor

Edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "weld-fs": {
      "command": "weld",
      "args": [
        "run", "--name", "fs",
        "--rules", "/absolute/path/to/weld.rules",
        "--", "npx", "-y", "@modelcontextprotocol/server-filesystem",
        "/path/to/project"
      ]
    }
  }
}
```

### Generic stdio pattern

Any client that lets you set `command` + `args` for an MCP server can run
weld:

```json
{
  "command": "weld",
  "args": ["run", "--name", "fs", "--rules", "/abs/path/weld.rules", "--", "<server-cmd>"]
}
```

---

## 6. Verifying the integration

### Test the proxy manually

```bash
# Start weld in front of a filesystem server.
weld run --name fs --rules ./weld.rules -- \
  npx -y @modelcontextprotocol/server-filesystem .

# In another terminal, send an initialize request.
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | \
  weld run --name fs --rules ./weld.rules -- \
  npx -y @modelcontextprotocol/server-filesystem .
```

You should see the raw initialize response on stdout.

### Test a denied call

Send a `tools/call` for a tool that would violate a deny rule. You should
receive:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32602,
    "message": "weld: blocked by rule 0: ...",
    "data": { "event": "fs.write", "rule": 0, "reason": "..." }
  }
}
```

### Check the audit log

```bash
weld verify
```

---

## 7. Troubleshooting

### The agent bypasses weld entirely

Claude Code, opencode, Cursor, and similar tools have **native tools**
(file edits, shell execution) that don't go through MCP. Weld can't
intercept those. Solutions:

1. **Deny native tools** in the client's permission settings (see the
   opencode example above) so all side effects flow through MCP.
2. **Use the shim** for shell commands: `weld shim -- <cmd>`.
3. **Restrict the agent's tool list** to weld-proxied servers only.

### The proxy hangs on startup

- Make sure the server command is correct and runs on its own.
- Check that `weld` itself is on the client's PATH — use absolute paths
  in configs.

### Tools show up but calls fail

- Confirm `--rules` points to a valid rules file (`weld check --rules ...`).
- Check `.weld/audit.jsonl` for the deny reason.

### Path guards don't match

- Weld canonicalizes path arguments (`~` expansion, `..` resolution).
  Your `set` patterns should match the canonicalized form — prefer
  absolute patterns like `/home/user/project/**` in rules files, or
  project-relative patterns like `./**` if you always run from the
  project root.

<div align="center">

# Codemagic MCP Server

</div>

---

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-cross--platform-lightgrey.svg)
![Build Status](https://img.shields.io/badge/build-passing-green.svg)
![](https://badge.mcpx.dev?type=server 'MCP Server')

</div>

---

A lightweight, community-maintained [Model Context Protocol (MCP)](https://github.com/modelcontextprotocol) server that provides seamless access to `Codemagic CI/CD` APIs. Built for agents, AI-native workflows, and for use of MCP-compatible clients.

---

## 🌐 How can you use this

**You:** What applications do I have on Codemagic?  
**Assistant:** *calls `get_all_applications()` and displays the list.*

**You:** Start a new build for my Flutter app  
**Assistant:** *calls `start_build()` with appropriate parameters*

**You:** Can you get the artifacts from my last build?  
**Assistant:** *calls `get_builds()` to find the latest build and then `get_artifact()` to download the files*

**You:** Show me the cache usage for my app  
**Assistant:** *calls `get_app_caches()` and displays storage information*

---

## 🌐 Getting started

### 1. Clone this repository

```bash
git clone https://github.com/stefanoamorelli/codemagic-mcp.git
cd codemagic-mcp
```

### 2. Set up your API key

Follow the [official documentation](https://docs.codemagic.io/rest-api/codemagic-rest-api/).

### 3. Install the MCP server in your client

For example, for [Claude Desktop](https://claude.ai/download): 

```
{
  "mcpServers": {
    "Codemagic MCP Server": {
      "command": "uv",
      "args": [
        "run",
        "--with",
        "mcp[cli]",
        "--with",
        "requests",
        "mcp",
        "run",
        "<global_path_to_the_cloned_repo>/codemagic_mcp/server.py"
      ],
      "env": {
        "PYTHONPATH": "<global_path_to_the_cloned_repo>/",
        "CODEMAGIC_API_KEY": "your-api-key-here"
      }
    },
}
```

---

## 📈 What this server can do

Interact with Codemagic CI/CD using natural language.

Tools marked **(admin)** are only registered when `CODEMAGIC_MCP_ENABLE_ADMIN=1`.

| API Category | Tools |
|:---|:---|
| **Applications API** | `get_all_applications`, `get_application`, `refresh_app_branches`, `add_application` (admin), `add_application_private` (admin) |
| **Artifacts API** | `get_artifact`, `create_public_artifact_url` (admin) |
| **Builds API** | `start_build`, `get_builds`, `get_build_status`, `cancel_build`, `get_build_step_log` |
| **Caches API** | `get_app_caches`, `delete_all_app_caches` (admin), `delete_app_cache` (admin) |
| **Teams API** | `invite_team_member` (admin), `delete_team_member` (admin) |

---

## Security

This server hands an AI agent a token that can start builds, read logs and change your team.
Two of its tools read untrusted input: `get_build_step_log` and `get_artifact` return whatever
ran in your CI, including text written by anyone who can push a commit. A poisoned log line is
one way an agent gets talked into doing something you did not ask for.

**The defaults are the safe configuration.** Only read and build tools are registered. Anything
that creates, deletes, invites, or publishes a public link stays unregistered until you opt in.

| Variable | Default | What it does |
|:---|:---|:---|
| `CODEMAGIC_API_KEY` | *(required)* | Your Codemagic API token. |
| `CODEMAGIC_MCP_ENABLE_ADMIN` | unset (off) | Set to `1` to also register the (admin) tools: add app, delete caches, invite/remove team members, create public artifact URLs. |
| `CODEMAGIC_SSH_KEY_PASSPHRASE` | unset | Passphrase for `add_application_private`, so it never passes through the conversation. |
| `CODEMAGIC_MCP_MAX_TEXT_BYTES` | `100000` | Cap on returned log text. |
| `CODEMAGIC_MCP_MAX_PUBLIC_URL_TTL` | `86400` | Longest lifetime allowed for a public artifact URL. |

Built-in protections:

- **Identifiers are validated and percent-encoded** before going into a URL. Without this,
  `requests` resolves `../` and a crafted `app_id` could redirect a call to a different
  Codemagic endpoint using your token.
- **Private keys are read from disk**, not passed as a tool argument. `add_application_private`
  takes `ssh_key_path`, so the key never enters the conversation, the logs, or the model context.
- **Build logs are redacted and truncated** before they reach the model: private key blocks,
  GitHub/AWS/Slack tokens, JWTs, `KEY=value` secret assignments and your own Codemagic token.
  This is a backstop, not a guarantee. Treat CI logs as sensitive.
- **Artifacts download to a file** and the tool returns a path, rather than streaming a binary
  and any signing material inside it into the conversation.
- **Every HTTP call has a timeout**, so a hung connection cannot wedge the server.

---

## 🛠️ Development

Run the server locally for testing:

```bash
mcp dev codemagic_mcp/server.py
```

---

## 📚 References

- [Codemagic REST API Documentation](https://docs.codemagic.io/rest-api/overview/)
- [Model Context Protocol Documentation](https://modelcontextprotocol.io/)
- [Python MCP SDK](https://github.com/modelcontextprotocol/python-sdk)

---

## 📜 License

[MIT License](LICENSE) © 2025 Stefano Amorelli

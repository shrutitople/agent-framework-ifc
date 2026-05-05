# FIDES security samples

<<<<<<< HEAD
This folder contains runnable FIDES samples. Keep this README as the quick
=======
This folder contains two runnable FIDES samples that use
`agent_framework.foundry.FoundryChatClient`. Keep this README as the quick
>>>>>>> 7d4c3723a777da54ad9f567915b628c695acaa0c
entry point for choosing and running a sample; use
[FIDES_DEVELOPER_GUIDE.md](FIDES_DEVELOPER_GUIDE.md) for the architecture,
security model, middleware behavior, and API reference.

## What each sample demonstrates

| Sample | Focus | Demonstrates |
|--------|-------|--------------|
| `email_security_example.py` | Prompt injection defense | `SecureAgentConfig`, Foundry-backed email handling, `quarantined_llm`, and approval on policy violations |
| `repo_confidentiality_example.py` | Data exfiltration prevention | Confidentiality labels, Foundry-backed repository access, `max_allowed_confidentiality`, and approval before leaking private data |
<<<<<<< HEAD
| `mcp_url_fides_example.py` | Remote MCP URL + local IFC/FIDES | `SecureMCPToolProxy(url=...)`, MCP annotation auto-labeling, post-tool-call enforcement, and security audit logging |
| `mcp_workiq_teams_example.py` | Work IQ Teams MCP + MSAL auth | `SecureMCPToolProxy(url=...)` with OAuth bearer token, MSAL interactive sign-in, Work IQ Teams MCP integration |
=======
>>>>>>> 7d4c3723a777da54ad9f567915b628c695acaa0c

## Prerequisites

Run these samples from the `python/` directory with the repo development
environment available.

- Azure CLI authentication: `az login`
- `FOUNDRY_PROJECT_ENDPOINT` set in your environment
- `FOUNDRY_MODEL` set in your environment for the main agent deployment
- Local dev environment installed (for example, `uv sync --dev`)

<<<<<<< HEAD
Foundry-backed samples use `FOUNDRY_MODEL` for the main agent and keep the
quarantine client pinned to `gpt-4o-mini`.

For `mcp_url_fides_example.py`, set:

- `GITHUB_PAT` (GitHub Personal Access Token)
- `FOUNDRY_PROJECT_ENDPOINT` (Foundry project endpoint)
- `FOUNDRY_MODEL` (optional model override)
=======
Both samples use `FOUNDRY_MODEL` for the main agent and keep the quarantine
client pinned to `gpt-4o-mini`.
>>>>>>> 7d4c3723a777da54ad9f567915b628c695acaa0c

## Suppressing the experimental warning

The FIDES APIs in these samples are still experimental. Each sample includes a
short commented `warnings.filterwarnings(...)` snippet near the imports.
Uncomment it if you want to suppress the FIDES warning before using the
experimental APIs locally.

## Running the samples

### `email_security_example.py`

This sample simulates an inbox containing trusted and untrusted emails,
including prompt-injection attempts that try to force a privileged `send_email`
tool call.

Run it with:

```bash
uv run samples/02-agents/security/email_security_example.py --cli
uv run samples/02-agents/security/email_security_example.py --devui
```

What to look for:

- Untrusted email bodies are handled through the FIDES security flow
- `quarantined_llm` processes hidden content in isolation
- DevUI requests approval if the agent tries a blocked privileged action

### `repo_confidentiality_example.py`

This sample simulates a public issue that tries to trick the agent into reading
private repository secrets and posting them to a public channel.

Run it with:

```bash
uv run samples/02-agents/security/repo_confidentiality_example.py --cli
uv run samples/02-agents/security/repo_confidentiality_example.py --devui
```

What to look for:

- Reading public content keeps the context public
- Reading private content taints the context as private
- Posting private data to a public destination triggers an approval request

### `mcp_url_fides_example.py`

This sample connects directly to `https://api.githubcopilot.com/mcp/` but runs
MCP calls locally through `SecureMCPToolProxy(url=...)` so IFC/FIDES middleware
can enforce policy after tool calls.

Run it with:

```bash
uv run samples/02-agents/security/mcp_url_fides_example.py
uv run samples/02-agents/security/mcp_url_fides_example.py --attack
```

What to look for:

- Tools are auto-labeled from MCP `ToolAnnotations`
- Untrusted data is tracked/hidden by FIDES label middleware
- Write attempts from tainted context generate policy audit entries

### `mcp_workiq_teams_example.py`

This sample connects to a Work IQ Teams MCP server using MSAL (Microsoft
Authentication Library) for interactive Entra ID sign-in. It demonstrates
OAuth-based remote MCP connectivity with local FIDES enforcement.

Prerequisites for this sample:

- `FOUNDRY_PROJECT_ENDPOINT` (Foundry project endpoint)
- `FOUNDRY_MODEL` (optional model override, defaults to o4-mini)
- Microsoft 365 Copilot license in your tenant
- First run will open a browser for interactive Microsoft 365 sign-in

Run it with:

```bash
uv run samples/02-agents/security/mcp_workiq_teams_example.py
uv run samples/02-agents/security/mcp_workiq_teams_example.py --attack
```

What to look for:

- MSAL token acquisition and browser-based interactive sign-in
- OAuth bearer token integration with `MCPStreamableHTTPTool`
- MCP tools auto-labeled from Work IQ Teams annotations
- Policy enforcement for Teams operations (e.g., message posting)

## Where to find the details

For the full FIDES design and API details, see
[FIDES_DEVELOPER_GUIDE.md](FIDES_DEVELOPER_GUIDE.md), which covers:

- integrity and confidentiality labels
- label propagation and auto-hiding behavior
- policy enforcement middleware
- security tools such as `quarantined_llm` and `inspect_variable`
- `SecureAgentConfig` and manual integration patterns

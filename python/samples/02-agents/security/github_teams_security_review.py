# Copyright (c) Microsoft. All rights reserved.

"""GitHub + Work IQ Teams Security Review Agent.

This script creates a secure agent that:
1. Connects to a local github-mcp-server over stdio to read repository files.
2. Connects to the Work IQ Teams MCP server over Streamable HTTP to send messages.
3. Performs a security review of a design document and sends the results via Teams.

Both MCP connections are wrapped by SecureMCPToolProxy for automatic FIDES
security labeling from MCP ToolAnnotations hints.

Prerequisites:
    - GITHUB_PAT: GitHub Personal Access Token
    - FOUNDRY_PROJECT_ENDPOINT: Foundry project endpoint
    - FOUNDRY_MODEL: Model deployment name (defaults to o4-mini)
    - github-mcp-server binary on PATH (or set GITHUB_MCP_SERVER_PATH)
    - Entra ID credentials for Work IQ Teams MCP

Run:
    uv run samples/02-agents/security/github_teams_security_review.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any

import msal
from agent_framework import Agent, MCPStdioTool, MCPStreamableHTTPTool
from agent_framework.foundry import FoundryChatClient
from agent_framework.security import SecureAgentConfig, SecureMCPToolProxy
from azure.identity import AzureCliCredential
from dotenv import load_dotenv
from httpx import AsyncClient, Timeout

# Load environment variables
load_dotenv(Path(__file__).parent / ".env")
load_dotenv()

# =============================================================================
# Configuration
# =============================================================================

FOUNDRY_ENDPOINT = os.getenv("FOUNDRY_PROJECT_ENDPOINT")
FOUNDRY_MODEL = os.getenv("FOUNDRY_MODEL", "o4-mini")

GITHUB_PAT = os.getenv("GITHUB_PAT")
if not GITHUB_PAT:
    raise RuntimeError(
        "GITHUB_PAT environment variable is not set. "
        "Create a token at https://github.com/settings/tokens "
        "and set it in your .env file or environment."
    )

if not FOUNDRY_ENDPOINT:
    raise RuntimeError("FOUNDRY_PROJECT_ENDPOINT environment variable is not set.")

# Work IQ Teams MCP configuration
TENANT_ID = "090fc601-8371-4167-8b63-dd3a11028a43"
CLIENT_ID = "ec3a7b3c-4991-46fe-9be6-3b153c9cc931"
SCOPES = ["https://agent365.svc.cloud.microsoft/McpServers.Teams.All"]
MCP_URL = f"https://agent365.svc.cloud.microsoft/agents/tenants/{TENANT_ID}/servers/mcp_TeamsServer"


# =============================================================================
# Authentication
# =============================================================================


def _acquire_token_interactive() -> str:
    """Acquire an access token for Work IQ Teams MCP via MSAL device flow.

    Returns the access token string. Cached tokens are reused when available.
    """
    app = msal.PublicClientApplication(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
    )

    # Try cached token first
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(SCOPES, account=accounts[0])
        if result and "access_token" in result:
            return result["access_token"]

    # Fall back to device flow
    flow = app.initiate_device_flow(SCOPES)
    if "user_code" not in flow:
        error_desc = flow.get("error_description", str(flow))
        raise RuntimeError(f"Device flow initiation failed: {error_desc}")

    print(flow["message"])
    result = app.acquire_token_by_device_flow(flow)

    if result and "access_token" in result:
        return result["access_token"]

    error_desc = result.get("error_description", result.get("error", "unknown error"))
    raise RuntimeError(f"MSAL token acquisition failed: {error_desc}")
    # credential = AzureCliCredential()
    # token = credential.get_token("https://agent365.svc.cloud.microsoft/.default")
    # return token.token

# =============================================================================
# Helpers
# =============================================================================


def _print_tool_labels(tools: list[Any], *, label: str = "", limit: int = 6) -> None:
    """Print auto-assigned security labels for a list of tools."""
    if label:
        print(f"\n{label}")
    for func in tools[:limit]:
        props = getattr(func, "additional_properties", {}) or {}
        integrity = props.get("source_integrity", "-")
        max_conf = props.get("max_allowed_confidentiality", "-")
        accepts = props.get("accepts_untrusted", "-")
        kind = "source" if accepts else "sink"
        print(
            f"   {func.name:30s}  integrity={integrity:10s}  "
            f"max_conf={max_conf:8s}  accepts_untrusted={accepts}  ({kind})"
        )
    if len(tools) > limit:
        print(f"   ... and {len(tools) - limit} more tools")


# =============================================================================
# Main
# =============================================================================

QUERY = (
    "Perform a thorough security review of the architecture proposed in "
    "docs/teams-deployment-notification-preview-design.md file, deployhub repository. "
    "Send a message on Teams after you are done with it."
)


async def run() -> None:
    """Run the combined GitHub + Teams security review agent."""
    print("=" * 70)
    print("GitHub + Teams Security Review Agent")
    print("=" * 70)
    print()
    print(f"Query: {QUERY}")
    print()

    # 1. Acquire Work IQ Teams token
    print("Acquiring Work IQ Teams token via MSAL (device flow)...")
    token = _acquire_token_interactive()
    print("Token acquired.\n")

    # 2. Create Foundry chat clients
    credential = AzureCliCredential()
    chat_client = FoundryChatClient(
        project_endpoint=FOUNDRY_ENDPOINT,
        model=FOUNDRY_MODEL,
        credential=credential,
    )
    quarantine_client = FoundryChatClient(
        project_endpoint=FOUNDRY_ENDPOINT,
        model="gpt-4o-mini",
        credential=credential,
    )

    # 3. Set up GitHub MCP server (local binary over stdio)
    github_mcp = MCPStdioTool(
        name="github",
        command=os.getenv("GITHUB_MCP_SERVER_PATH", "github-mcp-server"),
        args=["stdio"],
        env={"GITHUB_PERSONAL_ACCESS_TOKEN": GITHUB_PAT},
        description="GitHub MCP server for repository operations",
    )

    # 4. Set up Work IQ Teams MCP server (Streamable HTTP)
    headers = {"Authorization": f"Bearer {token}"}

    async with AsyncClient(
        headers=headers,
        follow_redirects=True,
        timeout=Timeout(30.0, read=300.0),
    ) as mcp_http_client:
        teams_mcp = MCPStreamableHTTPTool(
            name="WorkIQTeams",
            url=MCP_URL,
            description="Work IQ Teams MCP server over Streamable HTTP",
            http_client=mcp_http_client,
        )

        # 5. Wrap both with SecureMCPToolProxy for auto-labeling
        async with (
            SecureMCPToolProxy(github_mcp) as secure_github,
            SecureMCPToolProxy(mcp_tool=teams_mcp) as secure_teams,
        ):
            print(f"Connected to GitHub MCP — {len(secure_github.tools)} tools")
            _print_tool_labels(secure_github.tools, label="GitHub tools:")

            print(f"\nConnected to Teams MCP — {len(secure_teams.tools)} tools")
            _print_tool_labels(secure_teams.tools, label="Teams tools:")

            # 6. Combine tools from both servers
            all_tools = secure_github.tools + secure_teams.tools

            # 7. Configure FIDES security
            config = SecureAgentConfig(
                auto_hide_untrusted=True,
                approval_on_violation=True,
                enable_policy_enforcement=True,
                quarantine_chat_client=quarantine_client,
            )

            # 8. Create the agent
            agent = Agent(
                client=chat_client,
                name="security_review_agent",
                instructions=(
                    "You are an expert security reviewer. You can read files from GitHub repositories "
                    "and send messages on Microsoft Teams.\n\n"
                    "When asked to perform a security review:\n"
                    "1. Read the specified document from GitHub\n"
                    "2. Analyze the architecture for security concerns (OWASP Top 10, "
                    "authentication, authorization, data protection, injection risks, etc.)\n"
                    "3. Produce a structured security review with findings and recommendations\n"
                    "4. Send the review summary via Teams as requested\n\n"
                    "Be thorough and specific in your security analysis."
                ),
                tools=all_tools,
                context_providers=[config],
            )

            # 9. Run the agent
            print(f"\nRunning agent...\n{'=' * 70}\n")
            response = await agent.run(QUERY)

            print(f"\nAgent Response:\n{'-' * 40}")
            print(response.text)

            # 10. Show audit log
            audit_log = config.get_audit_log()
            print(f"\nSecurity audit entries: {len(audit_log)}")
            for entry in audit_log:
                print(
                    f"  - function={entry.get('function', 'unknown')} "
                    f"reason={entry.get('reason', 'policy violation')}"
                )


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except RuntimeError as ex:
        print(f"\nError: {ex}", file=sys.stderr)
        sys.exit(1)

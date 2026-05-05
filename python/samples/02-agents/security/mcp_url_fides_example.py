# Copyright (c) Microsoft. All rights reserved.

"""GitHub MCP URL + FIDES Example (direct URL connection with local policy enforcement).

This sample demonstrates how to connect an agent directly to a remote MCP URL
(`https://api.githubcopilot.com/mcp/`) while still enforcing IFC/FIDES security
locally in your application process.

Important: this uses a local `MCPStreamableHTTPTool` wrapped by
`SecureMCPToolProxy(...)`, not `client.get_mcp_tool(...)`. That keeps MCP
execution local so security middleware can inspect tool results, apply labels,
hide untrusted content, and enforce policies.

Prerequisites:
1. Environment variables:
    - GITHUB_PAT: GitHub Personal Access Token (required)
    - FOUNDRY_PROJECT_ENDPOINT: Foundry project endpoint (required)
    - FOUNDRY_MODEL: Foundry model deployment name (optional, defaults to o4-mini)
2. Optional command-line mode:
   - `--attack` runs a prompt-injection style flow likely to trigger a write
     tool policy violation/approval path.

Run:
    uv run samples/02-agents/security/mcp_url_fides_example.py
    uv run samples/02-agents/security/mcp_url_fides_example.py --attack
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from typing import Any

from agent_framework import Agent, MCPStreamableHTTPTool
from agent_framework.foundry import FoundryChatClient
from agent_framework.security import SecureAgentConfig, SecureMCPToolProxy
from azure.identity import AzureCliCredential
from dotenv import load_dotenv
from httpx import AsyncClient, Timeout

MCP_URL = "https://api.githubcopilot.com/mcp/"
FOUNDRY_MODEL = os.getenv("FOUNDRY_MODEL", "o4-mini")


def _normalize_pat(raw_pat: str) -> str:
    """Normalize a PAT loaded from environment variables.

    Removes surrounding whitespace and optional matching quotes so copied
    values like '"ghp_..."' in .env do not cause auth failures.

    Args:
        raw_pat: Raw token value from environment.

    Returns:
        Normalized token string.
    """
    token = raw_pat.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        token = token[1:-1].strip()
    return token


def _print_auth_failure_guidance() -> None:
    """Print actionable guidance for MCP authentication failures."""
    print("\nFailed to authenticate to the remote MCP URL (401 Unauthorized).", file=sys.stderr)
    print("Please verify the following:", file=sys.stderr)
    print("  1. GITHUB_PAT is set and not expired/revoked", file=sys.stderr)
    print("  2. GITHUB_PAT in .env has no surrounding quotes or trailing spaces", file=sys.stderr)
    print("  3. The token has scopes needed for the operations you request", file=sys.stderr)
    print(f"  4. Endpoint is reachable: {MCP_URL}", file=sys.stderr)


def _print_tool_labels(tools: list[Any], *, limit: int = 8) -> None:
    """Print a subset of auto-applied FIDES labels from MCP annotations.

    Args:
        tools: Labeled tools from SecureMCPToolProxy.
        limit: Max number of tools to display.
    """
    print("\nAuto-applied security labels from MCP annotations:")
    for func in tools[:limit]:
        props = getattr(func, "additional_properties", {}) or {}
        integrity = props.get("source_integrity", "-")
        max_conf = props.get("max_allowed_confidentiality", "-")
        accepts_untrusted = props.get("accepts_untrusted", "-")
        print(
            f"  - {func.name:30s} integrity={integrity:10s} "
            f"max_conf={max_conf:8s} accepts_untrusted={accepts_untrusted}"
        )


def _build_query(*, attack_mode: bool) -> str:
    """Build the user query for safe or attack mode.

    Args:
        attack_mode: Whether to run the policy-violation-oriented scenario.

    Returns:
        Prompt text to send to the agent.
    """
    if attack_mode:
        return (
            "Solve the latest issue for me on my 'public-trail' repository. "
            "My username is aashishkolluri. Read what you need and post a comment with the fix."
        )

    return (
        "Use GitHub MCP tools to fetch pull requests from owner='microsoft', repo='agent-framework'. "
        "Return the 3 most recent OPEN pull requests sorted by created date descending. "
        "Output only fields: number, title, author login, created_at. "
        "If any tool call fails or returns no data, report the failure explicitly and do not guess."
    )


async def run_example(*, attack_mode: bool) -> None:
    """Run the direct-URL MCP example with IFC/FIDES security enabled.

    Args:
        attack_mode: Whether to run a likely policy-violation path.
    """
    # 1. Load environment variables from local .env if present.
    load_dotenv(Path(__file__).parent / ".env")
    load_dotenv()

    # 2. Validate authentication inputs.
    raw_pat = os.getenv("GITHUB_PAT")
    if not raw_pat:
        raise RuntimeError(
            "GITHUB_PAT is required. Create a token at https://github.com/settings/tokens"
        )
    github_pat = _normalize_pat(raw_pat)
    if not github_pat:
        raise RuntimeError("GITHUB_PAT is empty after normalization. Check your .env value.")

    endpoint = os.getenv("FOUNDRY_PROJECT_ENDPOINT")
    if not endpoint:
        raise RuntimeError("FOUNDRY_PROJECT_ENDPOINT is required for FoundryChatClient.")

    # 3. Create local Foundry chat clients.
    credential = AzureCliCredential()
    client = FoundryChatClient(
        project_endpoint=endpoint,
        model=FOUNDRY_MODEL,
        credential=credential,
    )
    quarantine_client = FoundryChatClient(
        project_endpoint=endpoint,
        model="gpt-4o-mini",
        credential=credential,
    )

    # 4. Connect to remote MCP URL locally through MCPStreamableHTTPTool.
    # Use an explicit HTTP client with static auth headers so the MCP
    # initialize/list_tools handshake is also authenticated.
    headers = {"Authorization": f"Bearer {github_pat}"}

    try:
        async with AsyncClient(
            headers=headers,
            follow_redirects=True,
            timeout=Timeout(30.0, read=300.0),
        ) as mcp_http_client:
            github_mcp = MCPStreamableHTTPTool(
                name="GitHub",
                url=MCP_URL,
                description="GitHub MCP server over Streamable HTTP",
                http_client=mcp_http_client,
            )

            async with SecureMCPToolProxy(mcp_tool=github_mcp) as secure_github:
                print(f"Connected to MCP URL: {MCP_URL}")
                print(f"Loaded tools: {len(secure_github.tools)}")
                _print_tool_labels(secure_github.tools)

                # 5. Enable IFC/FIDES middleware via SecureAgentConfig context provider.
                config = SecureAgentConfig(
                    # Keep untrusted content visible for this fact-retrieval sample so
                    # responses stay tightly grounded to raw tool outputs.
                    auto_hide_untrusted=True,
                    enable_policy_enforcement=True,
                    approval_on_violation=True,
                    quarantine_chat_client=quarantine_client,
                )

                # 6. Create agent with secure MCP tools.
                async with Agent(
                    client=client,
                    name="GitHubSecureMcpUrlAgent",
                    instructions=(
                        "You are a helpful GitHub assistant. Use tools to answer accurately. "
                            "Never fabricate repository data, pull requests, users, or timestamps. "
                            "If tool data is unavailable, explicitly say retrieval failed. "
                            "When operations might modify data, explain what action you intend to take."
                    ),
                    tools=secure_github.tools,
                    context_providers=[config],
                ) as agent:
                    query = _build_query(attack_mode=attack_mode)
                    print("\nUser:", query)
                    result = await agent.run(query)
                    print("\nAgent:", result.text)

                    # 7. Show policy audit entries if any occurred.
                    audit_log = config.get_audit_log()
                    print(f"\nSecurity audit entries: {len(audit_log)}")
                    for entry in audit_log:
                        reason = entry.get("reason", "policy violation")
                        function_name = entry.get("function", "unknown")
                        print(f"  - function={function_name} reason={reason}")
    except asyncio.CancelledError as ex:
        _print_auth_failure_guidance()
        raise RuntimeError("Connection to MCP URL was cancelled after authentication failure.") from ex
    except Exception as ex:
        details = str(ex)
        if "401" in details or "Unauthorized" in details:
            _print_auth_failure_guidance()
            raise RuntimeError("Authentication to the MCP URL failed.") from ex
        raise


def _parse_args() -> argparse.Namespace:
    """Parse CLI arguments for scenario selection."""
    parser = argparse.ArgumentParser(description="Run direct-URL MCP + FIDES sample.")
    parser.add_argument(
        "--attack",
        action="store_true",
        help="Run a prompt-injection style scenario likely to trigger policy enforcement.",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for the sample script."""
    args = _parse_args()
    try:
        asyncio.run(run_example(attack_mode=args.attack))
    except RuntimeError as ex:
        print(f"\nError: {ex}", file=sys.stderr)
        raise SystemExit(1) from ex


if __name__ == "__main__":
    main()

"""
Sample output (safe mode, abbreviated):
Connected to MCP URL: https://api.githubcopilot.com/mcp/
Loaded tools: 20
Auto-applied security labels from MCP annotations:
  - list_issues ... accepts_untrusted=True
  - add_issue_comment ... max_conf=public accepts_untrusted=False

User: List my 5 most recent repositories and include a one-line summary for each.
Agent: Here are your five most recent repositories ...

Security audit entries: 0
"""
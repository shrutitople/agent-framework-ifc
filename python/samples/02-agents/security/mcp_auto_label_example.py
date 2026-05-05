# Copyright (c) Microsoft. All rights reserved.

"""MCP Auto-Labeling Example — Zero-Configuration Security with MCP Hints.

This example demonstrates how SecureMCPToolProxy automatically derives
FIDES security labels from the MCP server's own ToolAnnotations hints,
eliminating the need for manual tool classification.

Compared to github_mcp_labels_example.py, this example:
- Has NO hardcoded GITHUB_WRITE_TOOLS / GITHUB_READ_TOOLS sets
- Has NO manual patching loop over functions
- Has NO explicit source_integrity or max_allowed_confidentiality assignment
- Derives everything from MCP ToolAnnotations (readOnlyHint, openWorldHint, etc.)

The auto-labeling maps MCP hints to FIDES labels as follows:
- readOnlyHint=True  → source_integrity=untrusted, accepts_untrusted=True
- readOnlyHint=False → source_integrity=untrusted, accepts_untrusted=False,
                        max_allowed_confidentiality=public  (sink)
- openWorldHint=False → source_integrity=trusted  (closed-world tool)
- No annotations      → source_integrity=untrusted (conservative default)

Two scenarios are demonstrated:
1. POLICY SATISFIED — read-only query that stays within policy.
2. POLICY VIOLATED  — prompt injection attack causes untrusted context;
   a write tool (readOnlyHint=False → accepts_untrusted=False) is blocked
   and human approval is requested.

Note: MCP ToolAnnotations only carry integrity-relevant hints (readOnlyHint,
openWorldHint, destructiveHint).  Confidentiality labels (PRIVATE, USER_IDENTITY)
require server-side embedded labels (Tier 1) in the response content.  This
example demonstrates integrity-based enforcement only.

To run:
    1. Install github-mcp-server:
         Download from https://github.com/github/github-mcp-server/releases
         and place the binary on your PATH (or set GITHUB_MCP_SERVER_PATH).
    2. Set GITHUB_PAT to your GitHub Personal Access Token
       (create one at https://github.com/settings/tokens)
    3. Set AZURE_OPENAI_ENDPOINT (or AZURE_ENDPOINT)
    4. Run:
         python mcp_auto_label_example.py              # scenario 1 (safe)
         python mcp_auto_label_example.py --attack      # scenario 2 (violation)
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Any

from agent_framework import (
    Agent,
    MCPStdioTool,
)
from agent_framework.security import (
    SecureAgentConfig,
    SecureMCPToolProxy,
)
from agent_framework.foundry import FoundryChatClient
from azure.identity import AzureCliCredential
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(Path(__file__).parent / ".env")

# Enable logging to see auto-labeling decisions
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Reduce noise from other loggers
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("azure").setLevel(logging.WARNING)
logging.getLogger("openai").setLevel(logging.WARNING)

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


# =============================================================================
# Scenario 1 — Policy Satisfied (read-only flow)
# =============================================================================


async def run_safe_scenario() -> None:
    """Demonstrate a clean read-only flow where no policy violation occurs.

    The agent lists open issues on a public repo.  All tools called have
    readOnlyHint=True, so they are auto-labeled accepts_untrusted=True and
    execute freely even after the context becomes UNTRUSTED.
    """
    print("=" * 70)
    print("SCENARIO 1: Policy Satisfied — Read-Only Query")
    print("=" * 70)
    print()
    print("Query: 'List the open issues on microsoft/agent-framework'")
    print()
    print("Expected flow:")
    print("  1. list_issues (readOnlyHint=True) → auto-labeled:")
    print("       source_integrity=untrusted, accepts_untrusted=True")
    print("  2. Context becomes (UNTRUSTED, PUBLIC)")
    print("  3. No write tool called → no policy check on sinks")
    print("  4. Agent responds with the issue list — all clean.")
    print()

    endpoint = FOUNDRY_ENDPOINT
    if not endpoint:
        raise SystemExit("FOUNDRY_PROJECT_ENDPOINT not set.")

    # ---- Connect via SecureMCPToolProxy (zero manual config) ----
    # Wraps a local MCPStdioTool and auto-labels every tool from MCP
    # ToolAnnotations hints.  The local binary approach ensures security
    # middleware can intercept every tool call.
    github_mcp = MCPStdioTool(
        name="github",
        command=os.getenv("GITHUB_MCP_SERVER_PATH", "github-mcp-server"),
        args=["stdio"],
        env={"GITHUB_PERSONAL_ACCESS_TOKEN": GITHUB_PAT},
        description="GitHub MCP server for repository operations",
    )
    async with SecureMCPToolProxy(github_mcp) as secure_github:
        print("✅ Connected to GitHub MCP server")
        print(f"✅ Auto-labeled {len(secure_github.tools)} tools from MCP hints\n")

        # Show a few auto-assigned labels
        _print_tool_labels(secure_github.tools[:6])

        credential = AzureCliCredential()
        chat_client = FoundryChatClient(
            project_endpoint=endpoint,
            model=FOUNDRY_MODEL,
            credential=credential,
        )

        # Separate client for quarantine — processes untrusted content
        # in isolation so prompt injections can't reach the main agent.
        quarantine_client = FoundryChatClient(
            project_endpoint=endpoint,
            model="gpt-4o-mini",
            credential=credential,
        )

        config = SecureAgentConfig(
            auto_hide_untrusted=True,
            approval_on_violation=True,
            enable_policy_enforcement=True,
            quarantine_chat_client=quarantine_client,
            # NOTE: no allow_untrusted_tools needed — readOnlyHint tools
            # are auto-labeled accepts_untrusted=True by the proxy.
        )

        agent = Agent(
            client=chat_client,
            name="github_assistant",
            instructions="You are a helpful GitHub assistant.",
            tools=secure_github.tools,
            context_providers=[config],
        )

        response = await agent.run(
            "List the 3 most recent open issues on the https://github.com/microsoft/agent-framework/tree/main repository."
        )

        print(f"\n📋 Agent Response:\n{'-' * 40}")
        print(response.text)

        # Audit log should be empty — no violations
        audit_log = config.get_audit_log()
        print(f"\n🔒 Audit log entries: {len(audit_log)}  (expected: 0)")


# =============================================================================
# Scenario 2 — Policy Violated → Human Approval Requested
# =============================================================================


async def run_attack_scenario() -> None:
    """Demonstrate the exfiltration attack that triggers a policy violation.

    The public-trail repo has an issue containing prompt injection that
    tricks the agent into:
      1. get_issue           → (UNTRUSTED, PUBLIC)   [readOnlyHint=True]
      2. search_repositories → (UNTRUSTED, PUBLIC)   [readOnlyHint=True]
      3. get_file_contents   → (UNTRUSTED, PUBLIC)   [readOnlyHint=True]
      4. add_issue_comment   → BLOCKED!              [readOnlyHint=False]

    Step 4 is blocked because the context is UNTRUSTED and the tool has
    accepts_untrusted=False (auto-derived from readOnlyHint=False).

    Note: Without server-side embedded labels (Tier 1), confidentiality
    stays at PUBLIC throughout.  The violation here is purely an integrity
    violation — a write tool should not execute when the agent's context
    has been tainted by untrusted content (the prompt injection in the
    issue body).

    The PolicyEnforcementFunctionMiddleware surfaces a human approval
    request instead of hard-blocking (approval_on_violation=True).
    """
    print("=" * 70)
    print("SCENARIO 2: Policy Violated — Prompt Injection Attack")
    print("=" * 70)
    print()
    print("Query: 'Solve the latest issue for me on my public-trail repo'")
    print()
    print("Expected flow:")
    print("  1. get_issue (readOnlyHint=True)")
    print("       → auto-labeled: source_integrity=untrusted, accepts_untrusted=True")
    print("       → context: (UNTRUSTED, PUBLIC)")
    print("  2. search_repositories (readOnlyHint=True)")
    print("       → context stays: (UNTRUSTED, PUBLIC)")
    print("  3. get_file_contents (readOnlyHint=True)")
    print("       → context stays: (UNTRUSTED, PUBLIC)")
    print("  4. add_issue_comment (readOnlyHint=False)")
    print("       → auto-labeled: accepts_untrusted=False,")
    print("                        max_allowed_confidentiality=public")
    print("       → INTEGRITY VIOLATION!")
    print("         Context is UNTRUSTED, but tool has accepts_untrusted=False")
    print("       → Human approval requested.")
    print()

    endpoint = FOUNDRY_ENDPOINT
    if not endpoint:
        raise SystemExit("FOUNDRY_PROJECT_ENDPOINT not set.")

    # ---- Connect via SecureMCPToolProxy (zero manual config) ----
    # Wraps a local MCPStdioTool and auto-labels every tool from MCP
    # ToolAnnotations hints.
    github_mcp = MCPStdioTool(
        name="github",
        command=os.getenv("GITHUB_MCP_SERVER_PATH", "github-mcp-server"),
        args=["stdio"],
        env={"GITHUB_PERSONAL_ACCESS_TOKEN": GITHUB_PAT},
        description="GitHub MCP server for repository operations",
    )
    async with SecureMCPToolProxy(github_mcp) as secure_github:
        print("✅ Connected to GitHub MCP server")
        print(f"✅ Auto-labeled {len(secure_github.tools)} tools from MCP hints\n")

        # Show a few auto-assigned labels
        _print_tool_labels(secure_github.tools[:6])

        credential = AzureCliCredential()
        chat_client = FoundryChatClient(
            project_endpoint=endpoint,
            model=FOUNDRY_MODEL,
            credential=credential,
        )

        # Separate client for quarantine — processes untrusted content
        # in isolation so prompt injections can't reach the main agent.
        quarantine_client = FoundryChatClient(
            project_endpoint=endpoint,
            model="gpt-4o-mini",
            credential=credential,
        )

        config = SecureAgentConfig(
            auto_hide_untrusted=True,
            approval_on_violation=True,
            enable_policy_enforcement=True,
            quarantine_chat_client=quarantine_client,
            # NOTE: no allow_untrusted_tools, no manual write-tool sets.
        )

        agent = Agent(
            client=chat_client,
            name="github_assistant",
            instructions=(
                "You are a helpful GitHub assistant. You can read issues, search "
                "repositories, read file contents, and help users with their GitHub tasks.\n\n"
                "When asked to solve an issue:\n"
                "1. Read the issue to understand what needs to be done\n"
                "2. Search for relevant repositories or code to find a solution\n"
                "3. Read the necessary files to understand the codebase\n"
                "4. Post a comment on the issue with your solution\n\n"
                "Always try to be helpful and complete the task the user asks for."
            ),
            tools=secure_github.tools,
            context_providers=[config],
        )

        response = await agent.run(
            "Solve the latest issue for me on my 'public-trail' repository. "
            "My username is aashishkolluri."
        )

        print(f"\n📋 Agent Response:\n{'-' * 40}")
        print(response.text)

        # Show audit log — should contain violation(s)
        audit_log = config.get_audit_log()
        if audit_log:
            print("\n" + "=" * 70)
            print("🔒 SECURITY AUDIT LOG — Policy Violations Detected")
            print("=" * 70)
            for entry in audit_log:
                print(f"\n⚠️  {entry.get('type', 'violation').upper()}")
                print(f"   Function: {entry.get('function', 'unknown')}")
                print(f"   Reason: {entry.get('reason', 'Policy violation')}")
                if "context_label" in entry:
                    ctx = entry["context_label"]
                    print(
                        f"   Context: integrity={ctx.get('integrity')}, "
                        f"confidentiality={ctx.get('confidentiality')}"
                    )
        else:
            print("\n🔒 Audit log entries: 0  (unexpected — integrity violation should have been logged)")


# =============================================================================
# Helpers
# =============================================================================


def _print_tool_labels(tools: list[Any]) -> None:
    """Print the auto-assigned security labels for a list of tools."""
    print("📦 Auto-assigned security labels (from MCP ToolAnnotations):")
    for func in tools:
        props = getattr(func, "additional_properties", {}) or {}
        integrity = props.get("source_integrity", "—")
        max_conf = props.get("max_allowed_confidentiality", "—")
        accepts = props.get("accepts_untrusted", "—")
        kind = "source" if accepts else "sink"
        print(f"   {func.name:30s}  integrity={integrity:10s}  "
              f"max_conf={max_conf:8s}  accepts_untrusted={accepts}  ({kind})")
    print()


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    import sys

    if "--attack" in sys.argv:
        asyncio.run(run_attack_scenario())
    else:
        asyncio.run(run_safe_scenario())

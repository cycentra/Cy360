#!/usr/bin/env python3
"""
update_agent_commands.py
Reads the list of files changed in the latest commit, maps them to
agent domains, reads the changed source content, and asks Claude to
produce an updated .claude/commands/<agent>.md.

Usage:
  python3 scripts/update_agent_commands.py \
      --changed /tmp/changed_files.txt \
      --commands .claude/commands \
      --repo Cy360
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

# ── File → agent mapping for the Cy360 repo ──────────────────────────────────
# Each entry: agent_name → list of path prefixes/filenames it owns.
# A changed file triggers an agent if it starts with any listed prefix.
AGENT_DOMAINS = {
    "g-cyra-siem": [
        "backend/cysiemstack/",
        "backend/siem_proxy.py",
        "backend/blueprints/siem/",
    ],
    "g-cyra-asm": [
        "backend/cy_asm/",
        "backend/blueprints/asm/",
    ],
    "g-cyra-comp": [
        "backend/cy_comp/",
        "backend/blueprints/comp/",
    ],
    "g-cyra-rbac": [
        "backend/blueprints/auth/",
        "backend/blueprints/rbac/",
        "backend/blueprints/oidc/",
        "backend/core/config.py",
    ],
    "g-cyra-360": [
        "backend/app.py",
        "backend/blueprints/",
        "backend/core/",
        "portal/src/",
        "portal/public/",
    ],
    "g-cyra-devops": [
        "cycentra-setup.sh",
        ".github/workflows/deploy.yml",
        "pyproject.toml",
        "Dockerfile",
        "docker-compose",
        "RELEASE_NOTES.md",
    ],
    "g-cyra-test": [
        "tests/",
        ".github/workflows/",
    ],
    "g-cyra-bugfix": [
        "RELEASE_NOTES.md",
    ],
    "g-cyra-mgr": [
        ".github/agents/",
        "CLAUDE.md",
        ".claude/commands/",   # if agent specs themselves change
    ],
}

MAX_SOURCE_CHARS = 40_000   # cap total source content per agent call
MAX_DIFF_CHARS   = 20_000   # cap git diff per file


def get_diff(filepath: str) -> str:
    """Return the git diff for a single file (last commit)."""
    try:
        result = subprocess.run(
            ["git", "diff", "HEAD~1", "HEAD", "--", filepath],
            capture_output=True, text=True, timeout=15,
        )
        return result.stdout[:MAX_DIFF_CHARS]
    except Exception:
        return ""


def read_file_safe(filepath: str, max_chars: int = 8_000) -> str:
    """Read a file, capped at max_chars."""
    try:
        return Path(filepath).read_text(errors="replace")[:max_chars]
    except Exception:
        return ""


def affected_agents(changed_files: list[str]) -> dict[str, list[str]]:
    """Return {agent: [changed files it owns]}."""
    result: dict[str, list[str]] = {}
    for agent, prefixes in AGENT_DOMAINS.items():
        owned = [
            f for f in changed_files
            if any(f.startswith(p) or f == p for p in prefixes)
        ]
        if owned:
            result[agent] = owned
    return result


def build_source_block(files: list[str]) -> str:
    """Collect diffs (or full file if small) for all changed files."""
    parts = []
    total = 0
    for filepath in files:
        if total >= MAX_SOURCE_CHARS:
            parts.append(f"\n[truncated — too many changes to include all files]\n")
            break
        diff = get_diff(filepath)
        if diff:
            parts.append(f"### git diff: {filepath}\n```diff\n{diff}\n```\n")
            total += len(diff)
        else:
            content = read_file_safe(filepath)
            if content:
                parts.append(f"### full file: {filepath}\n```\n{content}\n```\n")
                total += len(content)
    return "\n".join(parts)


def update_command_file(
    agent: str,
    current_cmd: str,
    source_block: str,
    changed_files: list[str],
    repo: str,
) -> str | None:
    """Call Claude to produce an updated command file. Returns new content or None."""
    import anthropic

    client = anthropic.Anthropic()

    changed_list = "\n".join(f"  - {f}" for f in changed_files)

    prompt = f"""You are maintaining the Claude Code custom slash command file for the **{agent}** agent in the {repo} repository.

This file encodes the agent's domain knowledge: which files it owns, invariants it must never break, known bug patterns, routing rules, and implementation templates. It is loaded as the system context whenever a developer invokes `/{agent}` in Claude Code VS Code.

## Changed files in this commit
{changed_list}

## Source changes
{source_block}

## Current command file
{current_cmd}

## Task
Update the command file to reflect the code changes above. Rules:
1. Only change sections that are **factually outdated** by the diff. Do not rewrite for style.
2. If a new invariant, known bug pattern, or file path was added — add it to the right section.
3. If something was removed or renamed — update or remove the reference.
4. If the changes are cosmetic or unrelated to the agent's domain — output the command file UNCHANGED.
5. Preserve the `$ARGUMENTS` placeholder at the end exactly as-is.
6. Output ONLY the complete updated command file — no explanation, no markdown fences around the whole file, no commentary.
"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=8096,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text
    except Exception as e:
        print(f"  [ERROR] Claude API call failed for {agent}: {e}", file=sys.stderr)
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--changed",   required=True, help="File with list of changed paths")
    parser.add_argument("--commands",  required=True, help="Path to .claude/commands directory")
    parser.add_argument("--repo",      default="Cy360", help="Repo name for context")
    args = parser.parse_args()

    changed_files = [
        line.strip() for line in Path(args.changed).read_text().splitlines()
        if line.strip()
    ]
    if not changed_files:
        print("No changed files detected — nothing to do.")
        return

    commands_dir = Path(args.commands)
    agents = affected_agents(changed_files)

    if not agents:
        print("No agent domains affected by these changes — nothing to do.")
        return

    print(f"Agents affected: {', '.join(agents)}")

    for agent, files in agents.items():
        cmd_file = commands_dir / f"{agent}.md"
        if not cmd_file.exists():
            print(f"  [{agent}] command file not found at {cmd_file} — skipping")
            continue

        print(f"  [{agent}] updating — triggered by: {files}")
        current_cmd   = cmd_file.read_text()
        source_block  = build_source_block(files)

        if not source_block.strip():
            print(f"  [{agent}] no readable source changes — skipping")
            continue

        updated = update_command_file(agent, current_cmd, source_block, files, args.repo)
        if updated and updated.strip() != current_cmd.strip():
            cmd_file.write_text(updated)
            print(f"  [{agent}] ✅ updated")
        elif updated:
            print(f"  [{agent}] no changes needed (Claude determined content is still accurate)")
        else:
            print(f"  [{agent}] ⚠ skipped (API error)")


if __name__ == "__main__":
    main()

"""Agent hooks, instruction files and plugins."""

import glob
import os
import re

from .common import (
    MAX_REPOS,
    PAYLOAD_RE,
    _diff,
    _finding,
    _hash,
    _home,
    _json,
    _read,
    _short,
    repos,
)

_M_HOOKS = "toolchain_hooks"

INLINE_CODE_RE = re.compile(
    r"\bnode\s+-e\s|\bpython3?\s+-c\s|\bperl\s+-e\s|\bruby\s+-e\s"
    r"|\bdeno\s+eval\b|\bbun\s+-e\s",
    re.I)

INVISIBLE_RE = re.compile(
    "[​-‏‪-‮⁠-⁤⁦-⁩﻿]")

AGENT_DOC_NAMES = (
    "CLAUDE.md", "AGENTS.md", "AGENT.md", ".cursorrules", "GEMINI.md",
    ".windsurfrules", ".clinerules", "copilot-instructions.md",
)

PROJECT_HOOK_RELS = (
    ".claude/settings.json", ".claude/settings.local.json",
    ".vscode/tasks.json",
)


def _walk_hooks(node, acc):
    """Collect every {"type": "command", "command": …} anywhere in a hooks tree.

    The shape differs between tools and between versions of the same tool, so
    matching on structure rather than on an expected path means a vendor
    reorganising their schema does not silently turn this check off.
    """
    if isinstance(node, dict):
        cmd = node.get("command")
        if cmd and (node.get("type") in (None, "command")) and isinstance(cmd, str):
            acc.append(cmd)
        for v in node.values():
            _walk_hooks(v, acc)
    elif isinstance(node, list):
        for v in node:
            _walk_hooks(v, acc)
    return acc


def check_agent_hooks(store=None, hosts=("wsl", "win")):
    if "wsl" not in hosts:
        return []
    out, seen = [], {}
    home = _home()

    sources = [(os.path.join(home, ".claude", "settings.json"), "user"),
               (os.path.join(home, ".claude", "settings.local.json"), "user")]
    found, truncated = repos()
    for repo in found:
        for rel in PROJECT_HOOK_RELS:
            sources.append((os.path.join(repo, rel), "repo"))

    for path, scope in sources:
        if not os.path.isfile(path):
            continue
        doc = _json(path)
        if not isinstance(doc, dict):
            continue
        cmds = _walk_hooks(doc.get("hooks") or doc.get("tasks") or {}, [])
        for cmd in cmds:
            seen[f"{_short(path)}::{_hash(cmd)[:8]}"] = _hash(cmd)
            if PAYLOAD_RE.search(cmd):
                out.append(_finding(
                    "agent", "critical",
                    f"agent hook fetches and runs code ({_short(path)})",
                    f"`{cmd[:300]}` runs automatically on an agent or editor "
                    f"event. A hook is not a suggestion the tool shows you — it "
                    f"is a shell command the tool executes.",
                    _short(path)))
            elif scope == "repo":
                inline = INLINE_CODE_RE.search(cmd)
                out.append(_finding(
                    "agent", "high" if inline else "medium",
                    f"repository-supplied hook runs a command ({_short(path)})",
                    f"`{cmd[:300]}` — this hook ships with the repo, so cloning "
                    f"and opening it is enough to run it."
                    + (" The program is written inline in the config rather "
                       "than living in a reviewable file, which is common in "
                       "honest hooks and is also what makes a dishonest one "
                       "easy to miss in a diff." if inline else
                       " Verify it is yours."),
                    _short(path)))
            else:
                out.append(_finding(
                    "agent", "low", "agent hook configured",
                    f"`{cmd[:200]}` in your own settings — inventory, so a "
                    f"change to it is visible next run",
                    _short(path)))

    out.extend(_diff(store, _M_HOOKS, seen, "agent", "agent hook",
                     "a hook command that changed is a shell command that "
                     "changed, and it runs on the next tool event"))
    out.extend(_check_instruction_files(found))
    out.extend(_check_agent_plugins())
    if truncated:
        out.append(_finding(
            "visibility", "medium", "repository scan was truncated",
            f"stopped at {MAX_REPOS} repositories, so repo-scoped MCP servers, "
            f"hooks and git hooks below that cut-off are unaudited",
            "toolchain.repos"))
    if not seen:
        out.append(_finding(
            "agent", "ok", "no agent hooks configured",
            "no settings file defines a command hook, so no agent event "
            "currently executes a shell command", "~/.claude/settings.json"))
    return out


def _check_instruction_files(found_repos):
    """Agent instruction files carrying text hidden from the person reading them."""
    out, checked = [], 0
    candidates = []
    for name in AGENT_DOC_NAMES:
        candidates.append(os.path.join(_home(), name))
    for repo in found_repos:
        for name in AGENT_DOC_NAMES:
            candidates.append(os.path.join(repo, name))
            candidates.append(os.path.join(repo, ".github", name))
        candidates.extend(glob.glob(os.path.join(repo, ".cursor", "rules", "*")))
        candidates.extend(glob.glob(os.path.join(repo, ".claude", "*.md")))
        candidates.extend(glob.glob(
            os.path.join(repo, ".claude", "skills", "*", "*.md")))

    for path in candidates:
        if not os.path.isfile(path):
            continue
        checked += 1
        text = _read(path, 200000)
        hits = INVISIBLE_RE.findall(text)
        if hits:
            line_no = 1
            for i, ch in enumerate(text):
                if INVISIBLE_RE.match(ch):
                    line_no = text.count("\n", 0, i) + 1
                    break
            out.append(_finding(
                "agent", "high",
                f"hidden characters in an agent instruction file: {_short(path)}",
                f"{len(hits)} zero-width or bidirectional-override characters, "
                f"first at line {line_no}. These render as nothing to you and "
                f"as text to the model, which is the documented way to put an "
                f"instruction in a file that a human reviewer cannot see.",
                _short(path)))
    if checked and not out:
        out.append(_finding(
            "agent", "ok", "agent instruction files carry no hidden text",
            f"{checked} instruction and skill files scanned for zero-width and "
            f"bidi-override characters; every one is legible as written",
            "agent instructions"))
    return out


def _check_agent_plugins():
    """Third-party agent plugins and the marketplaces they came from."""
    out = []
    base = os.path.join(_home(), ".claude", "plugins")
    installed = _json(os.path.join(base, "installed_plugins.json"))
    markets = _json(os.path.join(base, "known_marketplaces.json"))
    names = []
    node = installed
    if isinstance(node, dict) and isinstance(node.get("plugins"), dict):
        node = node["plugins"]          # {"version": 2, "plugins": {...}}
    if isinstance(node, dict):
        for key, val in node.items():
            if isinstance(val, dict):
                names.extend(f"{key}/{k}" for k in val)
            elif isinstance(val, list):
                names.extend(f"{key}/{v}" for v in val)
            else:
                names.append(str(key))
    elif isinstance(node, list):
        names = [str(x) for x in node]

    market_names = []
    if isinstance(markets, dict):
        market_names = list(markets.keys())

    if names:
        out.append(_finding(
            "agent", "medium" if market_names else "low",
            f"{len(names)} agent plugin(s) installed",
            "third-party plugins run with the agent's full tool access: "
            + ", ".join(names[:12])
            + (f" — from marketplace(s): {', '.join(market_names[:6])}. "
               "Marketplace skills were used to distribute credential stealers "
               "in 2026, so treat an unfamiliar entry here the way you would an "
               "unfamiliar browser extension." if market_names else ""),
            "~/.claude/plugins"))
    return out

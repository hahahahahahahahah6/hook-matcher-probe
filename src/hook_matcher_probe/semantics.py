"""Matcher semantics for Claude Code hooks.

Grounded in the official Claude Code hooks reference (code.claude.com/docs/en/hooks)
and community-verified behavior:

- ``"*"``, ``""`` or an omitted matcher matches every occurrence.
- A matcher containing only letters, digits, ``_`` or ``|`` is compared as an
  exact string (``|`` separates alternatives).
- Any other character makes the matcher a regex over the matched value.
- Several events (``Stop``, ``UserPromptSubmit``, ...) silently ignore matchers.

Regex matching is modelled as a full-string match (``re.fullmatch``), matching
the documented ``mcp__memory__.*`` guidance ("don't drop the trailing ``.*``").
Note: the runtime uses JavaScript regex syntax, so exotic patterns may differ
slightly from this Python model; the common cases are identical.
"""

import re

# Built-in tool names shipped with Claude Code. Extend at runtime with
# --known-tools for project-local tools (e.g. extra MCP servers you know).
NATIVE_TOOLS = [
    "Bash",
    "BashOutput",
    "Edit",
    "MultiEdit",
    "Write",
    "NotebookEdit",
    "NotebookRead",
    "Read",
    "Glob",
    "Grep",
    "LS",
    "TodoWrite",
    "Task",
    "WebFetch",
    "WebSearch",
    "Skill",
    "SlashCommand",
    "AskUserQuestion",
    "ExitPlanMode",
]

# Events whose matcher filters the tool name.
TOOL_EVENTS = frozenset({
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PermissionRequest",
    "PermissionDenied",
})

# Events that do not support matchers: a matcher field here is silently ignored
# (the hook fires on every occurrence). Not an error per the reference.
MATCHER_IGNORED_EVENTS = frozenset({
    "UserPromptSubmit",
    "PostToolBatch",
    "Stop",
    "CwdChanged",
    "TeammateIdle",
    "TaskCreated",
    "TaskCompleted",
    "WorktreeCreate",
    "WorktreeRemove",
    "MessageDisplay",
})

# Event -> list of known matcher values. None = open-ended domain that cannot
# be statically verified (custom agent types, filenames, model names, ...).
MATCHER_DOMAINS = {
    "PreToolUse": list(NATIVE_TOOLS),
    "PostToolUse": list(NATIVE_TOOLS),
    "PostToolUseFailure": list(NATIVE_TOOLS),
    "PermissionRequest": list(NATIVE_TOOLS),
    "PermissionDenied": list(NATIVE_TOOLS),
    "SessionStart": ["startup", "resume", "clear", "compact", "fork"],
    "Setup": ["init", "maintenance"],
    "SessionEnd": ["clear", "resume", "logout", "prompt_input_exit", "other"],
    "Notification": [
        "permission_prompt",
        "idle_prompt",
        "auth_success",
        "agent_needs_input",
        "agent_completed",
    ],
    "SubagentStart": None,
    "SubagentStop": None,
    "PreCompact": ["manual", "auto"],
    "PostCompact": ["manual", "auto"],
    "PreModelSwitch": None,
    "PostModelSwitch": None,
    "ConfigChange": [
        "user_settings",
        "project_settings",
        "local_settings",
        "policy_settings",
        "skills",
    ],
    "DirectoryAdded": ["slash_command", "register_repo_root"],
    "FileChanged": None,
    "StopFailure": [
        "rate_limit",
        "overloaded",
        "authentication_failed",
        "server_error",
    ],
    "InstructionsLoaded": [
        "session_start",
        "nested_traversal",
        "path_glob_match",
        "include",
        "compact",
    ],
    "UserPromptExpansion": None,
    "Elicitation": None,
    "ElicitationResult": None,
}

KNOWN_EVENTS = (
    set(MATCHER_DOMAINS) | set(MATCHER_IGNORED_EVENTS)
)

_DOMAIN_LABEL = {
    "PreToolUse": "tool names",
    "PostToolUse": "tool names",
    "PostToolUseFailure": "tool names",
    "PermissionRequest": "tool names",
    "PermissionDenied": "tool names",
}

# A bare MCP server prefix, e.g. "mcp__lab". As a hook matcher this is an exact
# string that matches no tool (measured: 0 firings in 42 calls), even though the
# same string works as a permission rule. Needs the trailing "__.*".
# The negative lookahead keeps fully-qualified names out of this bucket.
_BARE_MCP_PREFIX = re.compile(r"^mcp__(?!.*__)[A-Za-z0-9_-]+$")

# A fully-qualified MCP tool name, e.g. "mcp__lab__run_tests".
_FULL_MCP_TOOL = re.compile(r"^mcp__[A-Za-z0-9_-]+__[A-Za-z0-9_.-]+$")

# Synthetic MCP tool name used to sanity-check mcp__ regexes.
_MCP_SYNTHETIC = "mcp__example-server__example_tool"

# Characters that keep a matcher in "exact string" mode per the reference.
_EXACT_CHARS = re.compile(r"[A-Za-z0-9_|]+")


def classify_matcher(matcher):
    """Classify a matcher string.

    Returns ("all", None) for "", "*" or None; ("exact", [parts]) when the
    matcher contains only letters/digits/_/|; otherwise ("regex", pattern).
    """
    if matcher is None or matcher in ("", "*"):
        return ("all", None)
    if _EXACT_CHARS.fullmatch(matcher):
        return ("exact", matcher.split("|"))
    return ("regex", matcher)


def looks_like_glob(pattern):
    """Heuristic: did the author mean a glob (``Bash*``) instead of a regex?

    Legitimate regex idioms like ``mcp__lab__.*`` are not globs: only a bare
    ``*``/``?`` (one not forming ``.*``/``.?``) counts as glob intent.
    """
    if not pattern or ("*" not in pattern and "?" not in pattern):
        return False
    stripped = pattern.replace(".*", "").replace(".?", "")
    if "*" not in stripped and "?" not in stripped:
        return False
    return re.fullmatch(r"[A-Za-z0-9_|?*\[\].-]+", pattern) is not None


def compile_regex(pattern):
    """Compile a matcher regex, returning (compiled, error_message)."""
    try:
        return re.compile(pattern), ""
    except re.error as exc:
        return None, str(exc)


def domain_for_event(event, extra_tools=()):
    """Return (values_or_None, label) for an event's matcher domain."""
    if event in TOOL_EVENTS:
        values = list(MATCHER_DOMAINS[event]) + [t for t in extra_tools if t]
        return values, _DOMAIN_LABEL.get(event, "tool names")
    values = MATCHER_DOMAINS.get(event)
    label = {
        "SessionStart": "session-start reasons",
        "Setup": "setup triggers",
        "SessionEnd": "session-end reasons",
        "Notification": "notification types",
        "SubagentStart": "agent types",
        "SubagentStop": "agent types",
        "PreCompact": "compact triggers",
        "PostCompact": "compact triggers",
        "PreModelSwitch": "model names",
        "PostModelSwitch": "model names",
        "ConfigChange": "config sources",
        "DirectoryAdded": "directory-added sources",
        "FileChanged": "filenames",
        "StopFailure": "error types",
        "InstructionsLoaded": "load reasons",
        "UserPromptExpansion": "command names",
        "Elicitation": "MCP server names",
        "ElicitationResult": "MCP server names",
    }.get(event, "values")
    return values, label

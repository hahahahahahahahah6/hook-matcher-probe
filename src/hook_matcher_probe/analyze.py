"""Static analysis of Claude Code hook matchers.

For every (event, matcher) group in a settings file, simulate what the matcher
can match and report groups that can never fire, plus the reason why.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import semantics as S


@dataclass
class Finding:
    severity: str  # "never" | "warn" | "ok" | "error"
    event: str
    matcher: str
    reason: str
    suggestion: str = ""
    matched: list = field(default_factory=list)


@dataclass
class Report:
    findings: list
    groups: int = 0

    @property
    def never(self):
        return [f for f in self.findings if f.severity == "never"]

    @property
    def warns(self):
        return [f for f in self.findings if f.severity == "warn"]

    @property
    def errors(self):
        return [f for f in self.findings if f.severity == "error"]


def _check_exact_part(part, values, label):
    """Classify one exact-matcher alternative.

    Returns (status, reason, suggestion) where status is "ok", "maybe"
    (plausible but unverifiable) or "dead".
    """
    if part in values:
        return "ok", "", ""
    if S._FULL_MCP_TOOL.match(part):
        return (
            "maybe",
            "%r looks like a fully-qualified MCP tool name; it can only be "
            "verified against your configured MCP servers" % part,
            "",
        )
    if S._BARE_MCP_PREFIX.match(part):
        return (
            "dead",
            "bare MCP server prefix %r matches no tool: hook matchers compare "
            "exact strings, while permission rules use prefix semantics, so the "
            "same string that works in --allowedTools stays silent here "
            "(measured 0 firings in 42 calls)" % part,
            "use %r to match every tool on that server" % (part + "__.*"),
        )
    lowered = {v.lower(): v for v in values}
    if part.lower() in lowered:
        actual = lowered[part.lower()]
        return (
            "dead",
            "matchers are case-sensitive: %r matches nothing, but %r exists"
            % (part, actual),
            "use %r" % actual,
        )
    return (
        "dead",
        "%r matches no known %s" % (part, label),
        "check the spelling against the hooks reference",
    )


def analyze_matcher(event, matcher, extra_tools=()):
    """Analyze one matcher string for an event. Returns [Finding]."""
    values, label = S.domain_for_event(event, extra_tools)
    display = matcher if matcher is not None else "(omitted)"

    if values is None:
        return [Finding(
            severity="warn",
            event=event,
            matcher=display,
            reason="matcher domain for %s is open-ended (custom %s); "
                   "cannot statically verify it will fire" % (event, label),
        )]

    kind, payload = S.classify_matcher(matcher)

    if kind == "all":
        return [Finding(
            severity="ok",
            event=event,
            matcher=display,
            reason="matches every %s" % label,
            matched=list(values),
        )]

    if kind == "exact":
        parts = payload
        matched, dead, maybes = [], [], []
        for part in parts:
            status, reason, suggestion = _check_exact_part(part, values, label)
            if status == "ok":
                matched.append(part)
            elif status == "maybe":
                maybes.append((part, reason))
            else:
                dead.append((part, reason, suggestion))
        if dead and not matched and not maybes:
            part, reason, suggestion = dead[0]
            extra = " (%d of %d alternatives dead)" % (len(dead), len(parts)) \
                if len(parts) > 1 else ""
            return [Finding(
                severity="never",
                event=event,
                matcher=display,
                reason=reason + extra,
                suggestion=suggestion,
                matched=[],
            )]
        findings = []
        for part, reason, suggestion in dead:
            findings.append(Finding(
                severity="warn",
                event=event,
                matcher=display,
                reason="alternative %r never matches: %s" % (part, reason),
                suggestion=suggestion,
                matched=matched,
            ))
        for part, reason in maybes:
            findings.append(Finding(
                severity="warn",
                event=event,
                matcher=display,
                reason=reason,
                matched=matched,
            ))
        if not findings:
            findings.append(Finding(
                severity="ok",
                event=event,
                matcher=display,
                reason="matches: %s" % ", ".join(matched),
                matched=matched,
            ))
        return findings

    # kind == "regex"
    rx, err = S.compile_regex(payload)
    if rx is None:
        reason = "invalid regex: %s" % err
        suggestion = ""
        if S.looks_like_glob(payload):
            suggestion = ("looks like a glob, not a regex: matchers are "
                          "exact-or-regex, never globs")
        return [Finding(
            severity="never",
            event=event,
            matcher=display,
            reason=reason,
            suggestion=suggestion,
        )]

    matched = [v for v in values if rx.fullmatch(v)]
    # MCP tools are dynamic; sanity-check mcp__ regexes against plausible names.
    if payload.startswith("mcp__") and _mcp_regex_plausible(rx, payload):
        matched = matched or ["<mcp__server__tool> (plausible)"]
    if not matched:
        suggestion = ""
        if S.looks_like_glob(payload):
            suggestion = ("looks like a glob: as a regex it matches literal "
                          "strings, not prefixes; use %r for a prefix match"
                          % payload.replace("*", ".*").replace("?", "."))
        return [Finding(
            severity="never",
            event=event,
            matcher=display,
            reason="regex matches none of the %d known %s (full-string match)"
                  % (len(values), label),
            suggestion=suggestion,
        )]
    if S.looks_like_glob(payload):
        return [Finding(
            severity="warn",
            event=event,
            matcher=display,
            reason="looks like a glob: as a regex it only matches %s; use %r "
                   "for a prefix match"
                   % (", ".join(matched),
                      payload.replace("*", ".*").replace("?", ".")),
            matched=matched,
        )]
    return [Finding(
        severity="ok",
        event=event,
        matcher=display,
        reason="matches: %s" % ", ".join(matched[:8])
               + (" (+%d more)" % (len(matched) - 8) if len(matched) > 8 else ""),
        matched=matched,
    )]


_IF_RE = None


_MCP_GENERIC_NAMES = [
    "mcp__a__b",
    "mcp__server-name__tool_name",
    "mcp__x__write_stuff",
    "mcp__srv__AskUserQuestion",
]


def _leading_literal_run(pattern):
    """Literal characters at the start of a regex, before any metacharacter."""
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            out.append(pattern[i + 1])
            i += 2
            continue
        if ch in ".*+?^$[]{}()|":
            break
        out.append(ch)
        i += 1
    return "".join(out)


def _mcp_regex_plausible(rx, pattern):
    """Can this regex match the mcp__server__tool shape at all?"""
    candidates = list(_MCP_GENERIC_NAMES)
    if pattern.startswith("mcp__"):
        literal = _leading_literal_run(pattern)
        if literal.startswith("mcp__"):
            candidates.append(literal + "example_tool")
    return any(rx.fullmatch(c) for c in candidates)


def _parse_if_condition(cond):
    """Parse an ``if`` condition like ``Write(.env*)`` into (tool, glob)."""
    import re as _re
    m = _re.fullmatch(r"\s*([A-Za-z0-9_|-]+|\*)(?:\((.*)\))?\s*", cond or "")
    if not m:
        return None, None
    return m.group(1), m.group(2)


def analyze_if_condition(event, cond, extra_tools=()):
    """Analyze a hook entry's ``if`` condition. Returns [Finding]."""
    tool, _glob = _parse_if_condition(cond)
    findings = []
    if tool is None:
        return [Finding(
            severity="warn",
            event=event,
            matcher="(if: %s)" % cond,
            reason="could not parse 'if' condition; it will likely never match",
            suggestion="use the 'ToolName(glob)' form, e.g. 'Write(.env*)'",
        )]
    if tool == "*":
        return findings
    values, _label = S.domain_for_event(event, extra_tools)
    if values is None:
        return findings
    status, reason, suggestion = _check_exact_part(tool, values, "tool names")
    if status == "dead":
        findings.append(Finding(
            severity="never",
            event=event,
            matcher="(if: %s)" % cond,
            reason="'if' condition targets %s" % reason,
            suggestion=suggestion,
        ))
    return findings


def analyze_settings(data, extra_tools=()):
    """Analyze a parsed settings.json dict. Returns Report."""
    findings = []
    groups = 0

    if not isinstance(data, dict):
        return Report([Finding("error", "", "",
                               "settings root is not a JSON object")])
    hooks = data.get("hooks")
    if hooks is None:
        return Report([Finding("warn", "", "",
                               "no 'hooks' section in settings")])
    if not isinstance(hooks, dict):
        return Report([Finding("error", "", "",
                               "'hooks' is not an object")])

    if data.get("disableAllHooks") is True:
        findings.append(Finding(
            severity="warn", event="", matcher="",
            reason="'disableAllHooks' is true: every hook below is dormant",
        ))

    seen = {}
    for event, entries in hooks.items():
        if event not in S.KNOWN_EVENTS:
            findings.append(Finding(
                severity="never",
                event=event,
                matcher="",
                reason="unknown event %r: it never occurs, so nothing here "
                       "can fire; check the spelling against the hooks "
                       "reference" % event,
            ))
            continue
        if not isinstance(entries, list):
            findings.append(Finding(
                severity="error",
                event=event,
                matcher="",
                reason="expected an array of matcher groups for %r" % event,
            ))
            continue
        for entry in entries:
            groups += 1
            if not isinstance(entry, dict):
                findings.append(Finding(
                    severity="error", event=event, matcher="",
                    reason="matcher group is not an object"))
                continue
            matcher = entry.get("matcher")

            # Old hook format: top-level "command" instead of nested "hooks"
            # array. Files with errors are skipped entirely.
            if "command" in entry and "hooks" not in entry:
                findings.append(Finding(
                    severity="never",
                    event=event,
                    matcher=str(matcher) if matcher is not None else "(omitted)",
                    reason="old hook format (top-level 'command'): files with "
                           "errors are skipped entirely, so every hook in this "
                           "file is dead",
                    suggestion="nest commands under a 'hooks' array with "
                               "explicit 'type': 'command'",
                ))
                continue

            key = (event, matcher if matcher is not None else "")
            seen[key] = seen.get(key, 0) + 1

            if (event in S.MATCHER_IGNORED_EVENTS
                    and matcher not in (None, "", "*")):
                findings.append(Finding(
                    severity="warn",
                    event=event,
                    matcher=str(matcher),
                    reason="matcher is silently ignored for %s: the hook "
                           "fires on every occurrence, not just %r"
                           % (event, matcher),
                    suggestion="remove the matcher and branch inside the "
                               "hook script if you need filtering",
                ))
                matcher_for_domain = None  # not applicable
            else:
                matcher_for_domain = matcher

            hook_list = entry.get("hooks", [])
            if isinstance(hook_list, list) and not hook_list:
                findings.append(Finding(
                    severity="warn",
                    event=event,
                    matcher=str(matcher) if matcher is not None else "(omitted)",
                    reason="matcher group has an empty 'hooks' array: "
                           "nothing will run even when the matcher fires",
                ))
            elif isinstance(hook_list, list):
                for hook in hook_list:
                    if not isinstance(hook, dict):
                        continue
                    if hook.get("type") not in (None, "command"):
                        findings.append(Finding(
                            severity="warn",
                            event=event,
                            matcher=str(matcher) if matcher is not None
                            else "(omitted)",
                            reason="unknown hook type %r (expected 'command')"
                                   % (hook.get("type"),),
                        ))
                    if "if" in hook and hook["if"]:
                        findings.extend(analyze_if_condition(
                            event, hook["if"], extra_tools))

            if matcher_for_domain is None:
                continue
            if event in S.MATCHER_IGNORED_EVENTS:
                continue  # matcher ignored; nothing to simulate
            findings.extend(analyze_matcher(event, matcher, extra_tools))

    for (event, matcher), count in seen.items():
        if count > 1:
            findings.append(Finding(
                severity="warn",
                event=event,
                matcher=matcher or "(omitted)",
                reason="duplicate matcher group (%d identical groups); later "
                       "groups are redundant" % count,
            ))

    return Report(findings, groups)


def explain_matcher(pattern, event="PreToolUse", extra_tools=()):
    """Explain what one matcher would match for an event. Returns [Finding]."""
    if event not in S.KNOWN_EVENTS:
        return [Finding("error", event, pattern,
                        "unknown event %r" % event)]
    if event in S.MATCHER_IGNORED_EVENTS:
        return [Finding("warn", event, pattern,
                        "matcher is silently ignored for %s" % event)]
    return analyze_matcher(event, pattern, extra_tools)

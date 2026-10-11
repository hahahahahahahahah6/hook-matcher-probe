# hook-matcher-probe

A stethoscope for Claude Code hook matchers: statically simulates every
`matcher` in your `settings.json` and reports the ones that can **never fire**,
with the reason why.

The motivating case is a real, measured failure mode. A hook matcher of
`mcp__lab` — the natural way to name a whole MCP server, and a string that
works fine as a permission rule — fired **0 times in 42 calls** to that
server's tools, while `mcp__lab__.*` fired 42 of 42. Hook matchers compare
exact strings (or regex); permission rules use prefix semantics. Nothing
errors. The settings file loads, the session runs, and the hook just never
starts. ([measured on dev.to](https://dev.to/rulestack/claude-codes-hook-matcher-mcplab-fired-0-times-in-42-calls-though-the-same-string-worked-as-a-250o))

`probe` finds that class of bug — and a dozen sibling silent failures — before
you waste a debugging session wondering why your hook never ran.

## Install

```bash
pip install hook-matcher-probe
```

Requires Python 3.9+. Stdlib only — no dependencies.

## Usage

```bash
# Analyze a settings file (exit 1 if any matcher can never fire: CI-friendly)
probe ~/.claude/settings.json
probe .claude/settings.json --json

# Test a single matcher without a file
probe explain "mcp__lab"
probe explain "Edit|Write" --event PostToolUse

# Teach it about your project-local tools
probe settings.json --known-tools "MyTool,mcp__internal__deploy"
```

Example output:

```
$ probe settings.json
hook-matcher-probe: 3 matcher group(s) analyzed
[NEVER-FIRES] PreToolUse matcher=mcp__lab
    bare MCP server prefix 'mcp__lab' matches no tool: hook matchers compare
    exact strings, while permission rules use prefix semantics, so the same
    string that works in --allowedTools stays silent here (measured 0 firings
    in 42 calls)
    suggestion: use 'mcp__lab__.*' to match every tool on that server
[WARN] Stop matcher=Bash
    matcher is silently ignored for Stop: the hook fires on every occurrence,
    not just 'Bash'
    suggestion: remove the matcher and branch inside the hook script if you
    need filtering
[ok] PreToolUse matcher=Edit|Write
    matches: Edit, Write
result: 1 never-fire(s), 0 error(s), 1 warning(s)
```

### What it detects

**Never-fires:**
- Bare MCP server prefixes (`mcp__lab`) — the permission-rule divergence above
- Case mismatches (`bash` vs `Bash`; matchers are case-sensitive, with a fix suggestion)
- Glob-shaped matchers (`Bash*`, `*Edit`) — matchers are exact-or-regex, never globs
- Invalid regexes
- Tool names on the wrong event (`Bash` on `SessionStart`, whose matchers filter session-start reasons)
- Unknown event names (typos like `PreTooluse` never occur)
- Dead `if` conditions (`"if": "mcp__lab"` stayed silent in the same experiment)
- Old hook format (top-level `command`): files with errors are skipped entirely, so every hook in the file is dead

**Warnings:**
- Matchers on events that silently ignore them (`Stop`, `UserPromptSubmit`, …) — the hook fires on *every* occurrence
- Partially dead alternations (`Edit|Write|Nope`)
- Empty `hooks` arrays, duplicate matcher groups, `disableAllHooks: true`

## Differentiation

**vs [canarygate](https://github.com/hahahahahahahahah6/canarygate):**
canarygate asks *"is the wire connected?"* — it checks hook liveness by
resolving commands and running real canary events through your hook scripts.
hook-matcher-probe is the stethoscope for one specific deep pit: **matcher
semantics**. It never executes anything; it statically simulates what each
matcher can match and names the exact semantic divergence when the answer is
"nothing" — the `mcp__lab` permission-vs-matcher trap, glob-vs-regex
confusion, case sensitivity, matchers on events that ignore them. Pure static
analysis, stdlib-only, milliseconds in CI. Use canarygate to prove the hook
runs; use this to prove the matcher routes to it.

## Matcher semantics modelled

From the [official hooks reference](https://code.claude.com/docs/en/hooks) and
community-verified behavior:

| Matcher | Meaning |
|---|---|
| `""`, `"*"`, omitted | matches everything |
| letters/digits/`_`/`|` only | exact string (`|` = alternatives) |
| anything else | regex over the matched value (full-string match) |

Events `UserPromptSubmit`, `PostToolBatch`, `Stop`, `CwdChanged`,
`TeammateIdle`, `TaskCreated`, `TaskCompleted`, `WorktreeCreate`,
`WorktreeRemove`, `MessageDisplay` silently ignore matchers. Other events
filter their own domain (tool names, session-start reasons, notification
types, …). See also:
[every matcher value by event](https://dev.to/aicoding-guide/every-value-you-can-put-in-a-claude-code-hook-matcher-by-event-5c8a)
and [the new matcher format](https://dev.to/jeremy_longshore/fixing-claude-code-hooks-the-new-matcher-format-3pep).

Caveat: the runtime uses JavaScript regex syntax; this tool models it with
Python `re.fullmatch`. The common cases are identical; exotic patterns may
differ slightly.

## License

MIT — see [LICENSE](LICENSE).

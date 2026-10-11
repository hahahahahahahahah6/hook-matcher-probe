"""Smoke tests for hook-matcher-probe (stdlib unittest)."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hook_matcher_probe import analyze as A  # noqa: E402
from hook_matcher_probe import semantics as S  # noqa: E402
from hook_matcher_probe.cli import main  # noqa: E402


def settings_for(*groups):
    return {"hooks": {"PreToolUse": list(groups)}}


def group(matcher, hooks=None, **kw):
    g = {"matcher": matcher,
         "hooks": hooks if hooks is not None else [
             {"type": "command", "command": "echo hi"}]}
    g.update(kw)
    return g


class TestExactMatchers(unittest.TestCase):
    def test_exact_tool_match_ok(self):
        rep = A.analyze_settings(settings_for(group("Bash")))
        self.assertEqual(rep.never, [])
        oks = [f for f in rep.findings if f.severity == "ok"]
        self.assertTrue(oks)
        self.assertIn("Bash", oks[0].matched)

    def test_case_mismatch_never_fires_with_suggestion(self):
        rep = A.analyze_settings(settings_for(group("bash")))
        self.assertEqual(len(rep.never), 1)
        f = rep.never[0]
        self.assertIn("case-sensitive", f.reason)
        self.assertIn("Bash", f.suggestion)

    def test_unknown_tool_never_fires(self):
        rep = A.analyze_settings(settings_for(group("EditFile")))
        self.assertEqual(len(rep.never), 1)
        self.assertIn("EditFile", rep.never[0].reason)

    def test_empty_matcher_matches_all(self):
        rep = A.analyze_settings(settings_for(group("")))
        self.assertEqual(rep.never, [])
        oks = [f for f in rep.findings if f.severity == "ok"]
        self.assertTrue(oks)
        self.assertGreater(len(oks[0].matched), 5)

    def test_pipe_list_partial_dead_warns_not_never(self):
        rep = A.analyze_settings(settings_for(group("Edit|Write|Nope")))
        self.assertEqual(rep.never, [])
        warns = [f for f in rep.findings if f.severity == "warn"]
        self.assertTrue(any("Nope" in w.reason for w in warns))

    def test_pipe_list_all_dead_is_never(self):
        rep = A.analyze_settings(settings_for(group("Nope|Nada")))
        self.assertEqual(len(rep.never), 1)


class TestMcpPrefixDivergence(unittest.TestCase):
    def test_bare_mcp_prefix_never_fires(self):
        rep = A.analyze_settings(settings_for(group("mcp__lab")))
        self.assertEqual(len(rep.never), 1)
        f = rep.never[0]
        self.assertIn("permission", f.reason)
        self.assertIn("mcp__lab__.*", f.suggestion)

    def test_mcp_wildcard_ok(self):
        rep = A.analyze_settings(settings_for(group("mcp__lab__.*")))
        self.assertEqual(rep.never, [])

    def test_full_mcp_tool_name_warns_unverifiable(self):
        rep = A.analyze_settings(settings_for(group("mcp__lab__run_tests")))
        self.assertEqual(rep.never, [])
        warns = [f for f in rep.findings if f.severity == "warn"]
        self.assertTrue(any("mcp__lab__run_tests" in w.reason for w in warns))


class TestRegexSemantics(unittest.TestCase):
    def test_glob_star_warns_with_prefix_hint(self):
        rep = A.analyze_settings(settings_for(group("Bash*")))
        self.assertEqual(rep.never, [])
        warns = [f for f in rep.findings if f.severity == "warn"]
        self.assertTrue(any("glob" in w.reason for w in warns))
        self.assertTrue(any("Bash.*" in w.reason for w in warns))

    def test_invalid_regex_never_fires(self):
        rep = A.analyze_settings(settings_for(group("*Edit")))
        self.assertEqual(len(rep.never), 1)
        self.assertIn("invalid regex", rep.never[0].reason)

    def test_regex_matching_tools_ok(self):
        rep = A.analyze_settings(settings_for(group("(Edit|Write)")))
        self.assertEqual(rep.never, [])
        oks = [f for f in rep.findings if f.severity == "ok"]
        self.assertTrue(any("Edit" in o.matched for o in oks))

    def test_classify_matcher_modes(self):
        self.assertEqual(S.classify_matcher("")[0], "all")
        self.assertEqual(S.classify_matcher("*")[0], "all")
        self.assertEqual(S.classify_matcher("Edit|Write")[0], "exact")
        self.assertEqual(S.classify_matcher("mcp__x__.*")[0], "regex")


class TestEventSemantics(unittest.TestCase):
    def test_matcher_on_stop_warns_silently_ignored(self):
        data = {"hooks": {"Stop": [group("Bash")]}}
        rep = A.analyze_settings(data)
        self.assertEqual(rep.never, [])
        warns = [f for f in rep.findings if f.severity == "warn"]
        self.assertTrue(any("silently ignored" in w.reason for w in warns))

    def test_unknown_event_never_fires(self):
        data = {"hooks": {"PreTooluse": [group("Bash")]}}
        rep = A.analyze_settings(data)
        self.assertEqual(len(rep.never), 1)
        self.assertIn("unknown event", rep.never[0].reason)

    def test_tool_matcher_on_session_start_never_fires(self):
        data = {"hooks": {"SessionStart": [group("Bash")]}}
        rep = A.analyze_settings(data)
        self.assertEqual(len(rep.never), 1)
        self.assertIn("session-start reasons", rep.never[0].reason)

    def test_session_start_reason_ok(self):
        data = {"hooks": {"SessionStart": [group("startup|resume")]}}
        rep = A.analyze_settings(data)
        self.assertEqual(rep.never, [])

    def test_old_format_command_is_never(self):
        data = {"hooks": {"Stop": [{"matcher": "",
                                    "command": "echo hi"}]}}
        rep = A.analyze_settings(data)
        self.assertEqual(len(rep.never), 1)
        self.assertIn("skipped entirely", rep.never[0].reason)

    def test_empty_hooks_array_warns(self):
        rep = A.analyze_settings(settings_for(group("Bash", hooks=[])))
        warns = [f for f in rep.findings if f.severity == "warn"]
        self.assertTrue(any("empty 'hooks' array" in w.reason for w in warns))

    def test_if_condition_bare_prefix_never_fires(self):
        g = group("Bash", hooks=[{"type": "command",
                                  "command": "echo hi",
                                  "if": "mcp__lab"}])
        rep = A.analyze_settings(settings_for(g))
        self.assertEqual(len(rep.never), 1)
        self.assertIn("mcp__lab", rep.never[0].reason)

    def test_if_condition_ok(self):
        g = group("Bash", hooks=[{"type": "command",
                                  "command": "echo hi",
                                  "if": "Bash(npm *)"}])
        rep = A.analyze_settings(settings_for(g))
        self.assertEqual(rep.never, [])


class TestExplain(unittest.TestCase):
    def test_explain_bare_mcp_prefix(self):
        findings = A.explain_matcher("mcp__lab")
        self.assertTrue(any(f.severity == "never" for f in findings))

    def test_explain_unknown_event(self):
        findings = A.explain_matcher("Bash", event="Nope")
        self.assertTrue(any(f.severity == "error" for f in findings))


class TestCli(unittest.TestCase):
    def _write(self, data):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        self.addCleanup(os.unlink, path)
        return path

    def test_cli_exit_1_on_never_fire(self):
        path = self._write(settings_for(group("bash")))
        self.assertEqual(main(["scan", path]), 1)

    def test_cli_exit_0_on_clean(self):
        path = self._write(settings_for(group("Bash")))
        self.assertEqual(main(["scan", path]), 0)

    def test_cli_exit_2_on_missing_file(self):
        self.assertEqual(main(["scan", "/nonexistent/x.json"]), 2)

    def test_cli_json_output(self):
        path = self._write(settings_for(group("bash")))
        proc = subprocess.run(
            [sys.executable, "-m", "hook_matcher_probe.cli",
             "scan", path, "--json"],
            capture_output=True, text=True,
            env={**os.environ,
                 "PYTHONPATH": os.path.join(os.path.dirname(__file__),
                                            "..", "src")})
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(payload["findings"][0]["severity"], "never")


if __name__ == "__main__":
    unittest.main()

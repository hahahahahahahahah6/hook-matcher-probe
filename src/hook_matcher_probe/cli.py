"""hook-matcher-probe: static probe for Claude Code hook matchers that never fire.

Usage:
    probe settings.json [--json] [--known-tools T1,T2] [--no-fail]
    probe explain "<matcher>" [--event PreToolUse]

Exit codes: 0 = no dead matchers, 1 = at least one never-fires finding,
2 = usage or file error.
"""

import argparse
import json
import sys

from . import analyze as A
from . import semantics as S

__version__ = "0.1.0"


def _format_text(report):
    lines = []
    lines.append("hook-matcher-probe: %d matcher group(s) analyzed" % report.groups)
    order = {"never": 0, "error": 1, "warn": 2, "ok": 3}
    for f in sorted(report.findings, key=lambda f: order.get(f.severity, 9)):
        tag = {"never": "NEVER-FIRES", "error": "ERROR",
               "warn": "WARN", "ok": "ok"}[f.severity]
        where = f.event or "(settings)"
        lines.append("[%s] %s matcher=%s" % (tag, where, f.matcher))
        lines.append("    %s" % f.reason)
        if f.suggestion:
            lines.append("    suggestion: %s" % f.suggestion)
    n_never = len(report.never)
    n_warn = len(report.warns)
    n_err = len(report.errors)
    if n_never == 0 and n_err == 0:
        lines.append("result: clean (%d warning(s))" % n_warn)
    else:
        lines.append("result: %d never-fire(s), %d error(s), %d warning(s)"
                     % (n_never, n_err, n_warn))
    return "\n".join(lines)


def _report_to_json(report):
    return {
        "groups": report.groups,
        "findings": [
            {"severity": f.severity, "event": f.event, "matcher": f.matcher,
             "reason": f.reason, "suggestion": f.suggestion,
             "matched": f.matched}
            for f in report.findings
        ],
    }


def _load_settings(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh), ""
    except FileNotFoundError:
        return None, "file not found: %s" % path
    except json.JSONDecodeError as exc:
        return None, "invalid JSON in %s: %s" % (path, exc)
    except OSError as exc:
        return None, "cannot read %s: %s" % (path, exc)


def cmd_scan(args):
    data, err = _load_settings(args.settings)
    if data is None:
        print("probe: %s" % err, file=sys.stderr)
        return 2
    extra = [t.strip() for t in (args.known_tools or "").split(",") if t.strip()]
    report = A.analyze_settings(data, extra_tools=extra)
    if args.json:
        print(json.dumps(_report_to_json(report), indent=2))
    else:
        print(_format_text(report))
    if args.no_fail:
        return 0
    if report.errors or report.never:
        return 1
    return 0


def cmd_explain(args):
    extra = [t.strip() for t in (args.known_tools or "").split(",") if t.strip()]
    kind, payload = S.classify_matcher(args.matcher)
    print("matcher: %r" % args.matcher)
    print("classified as: %s%s" % (kind, " (%s)" % "|".join(payload)
                                   if kind == "exact" else ""))
    print("event: %s" % args.event)
    for f in A.explain_matcher(args.matcher, args.event, extra_tools=extra):
        print("[%s] %s" % (f.severity.upper(), f.reason))
        if f.suggestion:
            print("suggestion: %s" % f.suggestion)
        if f.matched:
            print("would match: %s" % ", ".join(f.matched[:10]))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="probe",
        description="Static probe for Claude Code hook matchers that can "
                    "never fire.")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="analyze a settings.json file")
    s.add_argument("settings", help="path to settings.json")
    s.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    s.add_argument("--known-tools", default="",
                   help="extra comma-separated tool names to match against")
    s.add_argument("--no-fail", action="store_true",
                   help="always exit 0 even with never-fire findings")
    s.set_defaults(func=cmd_scan)

    e = sub.add_parser("explain", help="explain what one matcher would match")
    e.add_argument("matcher", help="matcher string to test")
    e.add_argument("--event", default="PreToolUse",
                   help="event to test against (default: PreToolUse)")
    e.add_argument("--known-tools", default="",
                   help="extra comma-separated tool names to match against")
    e.set_defaults(func=cmd_explain)
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Shorthand: "probe settings.json ..." == "probe scan settings.json ..."
    if argv and not argv[0].startswith("-") and argv[0] not in ("scan", "explain"):
        argv = ["scan"] + argv
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "func", None) is not None:
        return args.func(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

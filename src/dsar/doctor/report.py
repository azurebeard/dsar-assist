"""Rendering for `dsar doctor`.

Two formats: something an operator can read at a glance on a stage, and
something CI can assert on. Exit code is non-zero on any FAIL, so `doctor
--offline` works as a container smoke test without parsing anything.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict

from dsar import __version__
from dsar.doctor.checks import Verdict, run_checks

__all__ = ["run_doctor"]

_GLYPH = {
    Verdict.PASS: "  ok  ",
    Verdict.FAIL: " FAIL ",
    Verdict.WARN: " warn ",
    Verdict.SKIP: " skip ",
}


def run_doctor(offline: bool = False, as_json: bool = False) -> int:
    findings = list(run_checks(offline=offline))
    failed = sum(1 for f in findings if f.verdict is Verdict.FAIL)

    if as_json:
        payload = {
            "version": __version__,
            "offline": offline,
            "failed": failed,
            "findings": [
                {**asdict(f), "verdict": f.verdict.value} for f in findings
            ],
        }
        print(json.dumps(payload, indent=2))
        return 1 if failed else 0

    print(f"dsar {__version__} — doctor{' (offline)' if offline else ''}\n")
    for finding in findings:
        print(f"[{_GLYPH[finding.verdict]}] {finding.check}")
        print(f"          {finding.detail}")
        if finding.fix:
            for line in _wrap(finding.fix, 68):
                print(f"          → {line}")
        print()

    if failed:
        # stdout and stderr are separate streams to the same terminal; without
        # this the summary can appear above the findings it summarises.
        sys.stdout.flush()
        print(f"{failed} check(s) failed.", file=sys.stderr)
        return 1
    print("All checks passed.")
    return 0


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    for word in words:
        if current and sum(len(w) + 1 for w in current) + len(word) > width:
            lines.append(" ".join(current))
            current = [word]
        else:
            current.append(word)
    if current:
        lines.append(" ".join(current))
    return lines

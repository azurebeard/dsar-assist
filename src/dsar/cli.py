"""Command line surface.

Deliberately small. `up` runs the thing; `doctor` explains why it will not run.
Everything an operator is told to type in the documentation is one of these,
and a test greps the docs to keep that true.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from dsar import __version__
from dsar.logging_setup import configure_logging

__all__ = ["main", "build_parser"]

_PROG = "dsar"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=_PROG,
        description=(
            "Control plane for Microsoft Purview eDiscovery DSAR cases. "
            "No data plane: it never downloads, previews or stores item content."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"{_PROG} {__version__}"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="debug-level logging"
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    up = sub.add_parser("up", help="serve the control plane and open the UI")
    up.add_argument(
        "--port",
        type=int,
        default=None,
        help="override the listen port (default: DSAR_PORT, else 8765)",
    )
    up.add_argument(
        "--no-browser",
        action="store_true",
        help="do not try to open a browser (implied inside a container)",
    )

    audit = sub.add_parser("audit", help="read and verify the audit trail")
    audit_sub = audit.add_subparsers(dest="audit_command", metavar="<verb>")
    audit_verify = audit_sub.add_parser(
        "verify", help="recompute the hash chain and name the first break"
    )
    audit_verify.add_argument(
        "--json", action="store_true", dest="as_json", help="machine-readable"
    )
    audit_evidence = audit_sub.add_parser(
        "evidence", help="the per-case pack a data protection officer attaches"
    )
    audit_evidence.add_argument("case_id", help="the Purview case id")
    audit_evidence.add_argument(
        "--json", action="store_true", dest="as_json", help="machine-readable"
    )

    audit_tail = audit_sub.add_parser("tail", help="show the most recent records")
    audit_tail.add_argument(
        "-n", type=int, default=20, dest="count", help="how many (default 20)"
    )

    doctor = sub.add_parser(
        "doctor", help="diagnose configuration, packaging and connectivity"
    )
    doctor.add_argument(
        "--offline",
        action="store_true",
        help="skip every check that needs the network",
    )
    doctor.add_argument(
        "--json", action="store_true", dest="as_json", help="machine-readable output"
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(verbose=args.verbose)

    if args.command == "doctor":
        from dsar.doctor.report import run_doctor

        return run_doctor(offline=args.offline, as_json=args.as_json)

    if args.command == "audit":
        if getattr(args, "audit_command", None) == "evidence":
            from dsar.audit.report import run_evidence

            return run_evidence(args.case_id, as_json=getattr(args, "as_json", False))

        from dsar.audit.report import run_audit

        return run_audit(
            getattr(args, "audit_command", None),
            as_json=getattr(args, "as_json", False),
            count=getattr(args, "count", 20),
        )

    if args.command == "up":
        from dsar.web.app import serve

        return serve(port=args.port, open_browser=not args.no_browser)

    parser.print_help(sys.stderr)
    return 2

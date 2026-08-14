"""Entry point for both `dsar` and `python -m dsar`.

Two ways in, one implementation. The predecessor declared a console script that
was never installed, so every documented `dsar ...` invocation failed on a fresh
machine while the docs kept asserting it worked. CI now asserts that
`dsar --version`, `python -m dsar --version` and `docker run <image> --version`
all print the same string, so the two cannot drift apart unnoticed.
"""

from __future__ import annotations

import sys

from dsar.cli import main

if __name__ == "__main__":
    sys.exit(main())

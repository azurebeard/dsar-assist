"""The register is only worth having if it cannot drift.

`docs/CLAIMS.md` maps every guarantee to the thing that fails when it stops
being true. That document is prose, and prose rots — so these tests hold it to
the code in both directions:

  * a name in **Enforced by** must be a test that exists, so renaming or
    deleting one fails here rather than silently leaving a claim unguarded;
  * every structural test must appear in the register, so a new invariant
    cannot be added without a row.

The register exists because this project has six recorded instances of a stated
guarantee with no check behind it, every one found by accident. The point is
not the document. It is that an unenforced claim becomes a CI failure instead
of a discovery.
"""

from __future__ import annotations

import ast
import re

from conftest import REPO_ROOT

CLAIMS = REPO_ROOT / "docs" / "CLAIMS.md"

#: A register row: `| INV-nn | claim | stated in | enforced by | kind |`.
#:
#: The kind is matched case-insensitively. It was `[a-z-]+`, which silently
#: dropped the three rows whose kind is `CI` — so INV-31, INV-40 and INV-41
#: were invisible to every check in this file, including the one asserting
#: their named enforcement exists. Found by the row-count assertion added for
#: WS10 SEC-M-13, on its first run.
_ROW = re.compile(
    r"^\|\s*(INV-\d+)\s*\|(.+?)\|(.+?)\|(.+?)\|\s*([A-Za-z-]+)\s*\|\s*$",
    re.MULTILINE,
)

#: `test_name` in backticks, so prose in the same cell is ignored.
_TEST_NAME = re.compile(r"`(test_[a-z0-9_]+)`")


def _rows() -> list[tuple[str, str, str, str, str]]:
    """Every register row, with the count checked against the file.

    WS10 SEC-M-13: this parsed with a regex and asserted only that it found
    *something*. A row whose shape broke — a stray pipe, a missing column —
    silently dropped out and every test still passed, so the register could be
    wrong in exactly the way it exists to prevent.

    Counting `| INV-` line starts separately is the fix: the parse and the file
    must agree on how many claims there are.
    """
    text = CLAIMS.read_text(encoding="utf-8")
    rows = [tuple(part.strip() for part in match.groups()) for match in _ROW.finditer(text)]
    assert rows, "no rows parsed out of docs/CLAIMS.md — has the table shape changed?"

    declared = len(re.findall(r"^\|\s*INV-\d+\s*\|", text, re.MULTILINE))
    assert len(rows) == declared, (
        f"{declared} rows start with an INV number but only {len(rows)} parsed "
        f"— a malformed row is being silently ignored"
    )
    return rows  # type: ignore[return-value]


def _test_names() -> dict[str, str]:
    """Every test function in the suite, mapped to the file defining it.

    Collected by walking the AST rather than by asking pytest. `conftest.py`
    installs an autouse socket guard, so re-entrant collection is a bad idea
    for no gain — and every other scan in this project reads the source.

    A dict rather than a set, so two files defining the same name is caught
    rather than hidden.
    """
    found: dict[str, str] = {}
    for path in sorted((REPO_ROOT / "tests").glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("test_"):
                    previous = found.get(node.name)
                    assert previous is None, (
                        f"{node.name} is defined in both {previous} and {path.name}; "
                        f"the register keys on the name, so it must be unique"
                    )
                    found[node.name] = path.name
    return found


# --------------------------------------------------------------- the rows


def test_every_named_test_exists() -> None:
    """A register naming a test that does not exist is worse than no register:
    it reads as evidence and is not."""
    known = _test_names()
    missing: list[str] = []
    for inv, _claim, _stated, enforced, _kind in _rows():
        for name in _TEST_NAME.findall(enforced):
            if name not in known:
                missing.append(f"{inv} names {name}")
    assert missing == [], f"named in docs/CLAIMS.md but not defined: {missing}"


def test_every_row_names_an_enforcement() -> None:
    """An empty cell is a defect. `open` is a valid, visible answer — forcing
    every row to name a test would fill the register with fictional names,
    which is exactly the failure it exists to prevent."""
    blank = [inv for inv, _c, _s, enforced, _k in _rows() if not enforced.strip("— -")]
    assert blank == [], f"rows with no enforcement named: {blank}"


def test_an_open_claim_names_a_real_backlog_item() -> None:
    """An unenforced claim has to point somewhere. Otherwise `open` becomes a
    way of writing "we know" and never doing anything about it."""
    open_rows = [row for row in _rows() if row[4].lower() == "open"]
    if not open_rows:
        return  # nothing to point anywhere

    # The backlog lives in the project's private working notes (local/), which
    # is its own repository. An open claim must still point at a real item
    # there — read lazily, so a register with no open rows needs no backlog.
    backlog_path = REPO_ROOT / "local" / "docs" / "BACKLOG.md"
    assert backlog_path.exists(), (
        "the register has open rows but local/docs/BACKLOG.md does not exist "
        "on this machine — open claims must be traceable to a backlog item"
    )
    backlog = backlog_path.read_text(encoding="utf-8")
    dangling: list[str] = []
    for inv, _claim, _stated, enforced, kind in open_rows:
        items = re.findall(r"\bB-\d+\b", enforced)
        if not items:
            dangling.append(f"{inv} is open and names no backlog item")
        dangling += [
            f"{inv} names {item}, which is not in BACKLOG.md"
            for item in items
            if item not in backlog
        ]
    assert dangling == [], dangling


def test_the_numbers_are_unique() -> None:
    numbers = [inv for inv, *_ in _rows()]
    duplicates = sorted({n for n in numbers if numbers.count(n) > 1})
    assert duplicates == [], f"duplicate invariant numbers: {duplicates}"


def test_the_cited_numbers_still_mean_what_cites_them() -> None:
    """`INV-07` and `INV-10` are referenced from source. They were carried over
    from the predecessor, whose register was never rebuilt — this is that
    register, so those two numbers are not free to be reused."""
    rows = {inv: claim for inv, claim, *_ in _rows()}
    assert "INV-07" in rows and "dependency budget" in rows["INV-07"].lower()
    assert "INV-10" in rows and "network" in rows["INV-10"].lower()

    # And the citations must still be there, or the numbers are stranded again.
    assert "INV-07" in (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "INV-10" in (
        REPO_ROOT / "src" / "dsar" / "identity" / "expand.py"
    ).read_text(encoding="utf-8")


# ------------------------------------------------- the other direction


def test_every_structural_test_is_registered() -> None:
    """A new invariant cannot be added without a row.

    This is the direction that keeps the register honest over time. Without
    it the file is accurate on the day it is written and decorative a month
    later — which is what happened to the `INV-nn` scheme this revives.
    """
    registered = set()
    for _inv, _claim, _stated, enforced, _kind in _rows():
        registered |= set(_TEST_NAME.findall(enforced))

    structural = {
        node.name
        for node in ast.parse(
            (REPO_ROOT / "tests" / "test_structural.py").read_text(encoding="utf-8")
        ).body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    }
    unregistered = sorted(structural - registered)
    assert unregistered == [], (
        f"structural tests with no row in docs/CLAIMS.md: {unregistered}"
    )


def test_the_register_covers_the_claims_it_says_it_does() -> None:
    """A register that shrinks quietly is worse than none.

    WS10 mutated `CLAIMS.md` four ways — de-shaped a row, deleted one, pointed
    one at an unrelated real test, invented a claim — and all four passed. The
    row-count check in `_rows` closes the first two. This closes the "shrank"
    case from the other direction by pinning a floor, so deleting rows to make
    a failure go away is itself a failure.

    The floor is deliberately below the current count: rows are expected to be
    added, and a test that must be edited on every addition is a test people
    learn to edit.
    """
    rows = _rows()
    assert len(rows) >= 60, (
        f"the register has shrunk to {len(rows)} rows. Claims are not removed "
        f"because they became inconvenient; if one no longer applies, say so "
        f"in the row rather than deleting it."
    )


def test_every_enforcing_test_is_named_by_at_most_one_claim() -> None:
    """Two claims pointing at one test usually means the second is not really
    enforced — it is riding on a check written for something else."""
    from collections import Counter

    cited: Counter[str] = Counter()
    for inv, _claim, _stated, enforced, _kind in _rows():
        for name in set(_TEST_NAME.findall(enforced)):
            cited[name] += 1
    shared = {name: n for name, n in cited.items() if n > 1}
    assert shared == {}, (
        f"tests named by more than one claim: {shared}. Each is doing work for "
        f"a claim it may not actually cover."
    )

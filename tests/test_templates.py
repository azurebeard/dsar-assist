"""The narrowings, and the property that makes the delta mean anything.

Templates decide what a subject access response contains. A template that
narrows too far under-discloses, and under-disclosure is a compliance failure
rather than a cosmetic one — so the shipped definition file is asserted here
rather than trusted to review.

The comparability rules live in the front end because that is where the two
queries are; what is testable server-side is the flag the front end acts on and
the composition it acts on top of.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dsar.identity.kql import KqlError
from dsar.identity.templates import (
    TemplateError,
    compose,
    load_templates,
    render_template,
)

#: The narrowings measured on 2026-08-02 to reduce the site count to zero. Both
#: are mail-item properties. Named here so adding a third has to be a decision:
#: this is the list the interface warns about, and a template that silently
#: joins it is one whose zero site count reads as an empty estate.
MAILBOX_ONLY = {"workload", "attachments"}


@pytest.fixture(scope="module")
def templates() -> tuple:
    return load_templates()


def _by_id(templates: tuple) -> dict:
    return {t.id: t for t in templates}


# ------------------------------------------------------------- the shipped file


def test_the_shipped_definitions_load(templates: tuple) -> None:
    """An unknown builder or an unquotable fixed term fails at load. A template
    that fails at use looks exactly like a search with no results."""
    assert len(templates) >= 6


def test_mailbox_only_marks_exactly_the_measured_templates(templates: tuple) -> None:
    marked = {t.id for t in templates if t.mailbox_only}
    assert marked == MAILBOX_ONLY


def test_a_mailbox_only_template_also_carries_the_caution_in_prose(
    templates: tuple,
) -> None:
    """The flag drives the interface; the caution explains it. Losing either
    leaves an operator reading a zero site count as an empty estate."""
    for template in templates:
        if template.mailbox_only:
            assert "site" in template.caution.lower(), template.id


def test_mailbox_only_defaults_to_false(tmp_path: Path) -> None:
    definition = {
        "templates": [
            {
                "id": "plain",
                "name": "Plain",
                "purpose": "p",
                "builder": "phrase_or",
                "fixed_terms": ["grievance"],
                "inputs": [],
            }
        ]
    }
    path = tmp_path / "t.json"
    path.write_text(json.dumps(definition), encoding="utf-8")
    assert load_templates(path)[0].mailbox_only is False


def test_every_template_declares_what_it_costs(templates: tuple) -> None:
    """Purpose and guidance are not decoration. The operator choosing a
    narrowing is deciding the scope of somebody's subject access response."""
    for template in templates:
        assert template.purpose.strip(), template.id
        assert template.guidance.strip(), template.id


def test_a_duplicate_id_is_refused(tmp_path: Path) -> None:
    entry = {
        "id": "dup",
        "name": "D",
        "purpose": "p",
        "builder": "phrase_or",
        "fixed_terms": ["x"],
        "inputs": [],
    }
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"templates": [entry, entry]}), encoding="utf-8")
    with pytest.raises(TemplateError, match="duplicate"):
        load_templates(path)


def test_an_unknown_builder_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(
        json.dumps(
            {
                "templates": [
                    {
                        "id": "x",
                        "name": "X",
                        "purpose": "p",
                        "builder": "sql",
                        "inputs": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(TemplateError, match="unknown builder"):
        load_templates(path)


# ------------------------------------------------------------------ rendering


def test_the_workload_split_produces_the_clause_that_zeroes_sites(
    templates: tuple,
) -> None:
    """The measured behaviour, asserted so the flag above is about this clause
    and not a label that drifted off it."""
    rendered = render_template(_by_id(templates)["workload"], {"kind": "email"})
    assert rendered == "kind:email"


def test_a_choice_outside_the_definitions_own_options_is_refused(
    templates: tuple,
) -> None:
    with pytest.raises(TemplateError, match="choose one of"):
        render_template(_by_id(templates)["workload"], {"kind": "email OR im"})


def test_a_file_extension_is_allowlisted_not_escaped(templates: tuple) -> None:
    """`filetype:` takes a bare token, so it is the one value that reaches a
    query unquoted and cannot be made safe by quoting."""
    attachments = _by_id(templates)["attachments"]
    assert render_template(attachments, {"filetypes": "pdf"}) == "filetype:pdf"
    with pytest.raises(TemplateError, match="not a file extension"):
        render_template(attachments, {"filetypes": 'pdf" OR *'})


def test_a_term_that_cannot_be_quoted_is_refused_not_escaped(
    templates: tuple,
) -> None:
    """KQL has no portable escape for a quote inside a phrase, so escaping
    would silently change what was searched for.

    `KqlError` rather than `TemplateError` — the refusal comes from the quoting
    layer, and both are mapped to 400 by `api.handle`, which is what makes this
    an input error rather than a 500.
    """
    with pytest.raises(KqlError):
        render_template(
            _by_id(templates)["employment_file"], {"terms": 'he said "no"'}
        )


def test_a_narrowing_never_replaces_the_query_it_narrows(templates: tuple) -> None:
    existing = 'participants:"meganb@example.com" OR "Meg"'
    narrowed = render_template(
        _by_id(templates)["workload"], {"kind": "email"}, existing=existing
    )
    assert narrowed.startswith(f"({existing})")
    assert narrowed.endswith("AND kind:email")


# ------------------------------------------------------------------- compose


def test_compose_parenthesises_a_boolean_left_side() -> None:
    """`a OR b AND c` binds AND tighter, which reads as "a, or any c mentioning
    b" — wider than the query it was meant to narrow, and wrong in a way that
    still returns a believable number."""
    assert compose('"a" OR "b"', "kind:email") == '("a" OR "b") AND kind:email'


def test_compose_leaves_an_atomic_side_alone() -> None:
    assert compose("kind:email", "filetype:pdf") == "kind:email AND filetype:pdf"


def test_compose_does_not_mistake_two_groups_for_one() -> None:
    assert compose('("a") OR ("b")', "kind:email") == '(("a") OR ("b")) AND kind:email'


def test_compose_ignores_an_operator_inside_a_quoted_phrase() -> None:
    """A phrase containing the word AND is not a boolean, and bracketing it
    would be harmless — but treating it as one anywhere else would not be."""
    assert compose('"terms and conditions"', "kind:email") == (
        '"terms and conditions" AND kind:email'
    )


def test_compose_with_nothing_to_add_is_the_original() -> None:
    assert compose('participants:"a"', "") == 'participants:"a"'
    assert compose("", "kind:email") == "kind:email"


def test_the_api_surfaces_the_flag_the_interface_acts_on() -> None:
    """`mailbox_only` has to cross the wire, or the front end cannot warn.

    Called with an empty context on purpose: the endpoint reads the shipped
    definition file and nothing about the operator or their session, which is
    why it is safe for it to be the one read that touches no Graph call.
    """
    from typing import Any, cast

    from dsar.web.api import handle

    nothing = cast(Any, None)
    status, payload = handle(
        "/api/templates",
        {},
        principal=nothing,
        cases=nothing,
        config=nothing,
        workflow=nothing,
    )
    assert status == 200
    marked = {t["id"] for t in payload["templates"] if t["mailbox_only"]}
    assert marked == MAILBOX_ONLY

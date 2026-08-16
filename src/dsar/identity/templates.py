"""Standard DSAR query templates (Phase 5, alongside A-21).

Identity expansion answers *who*. These answer *what about them* — the handful
of scopings a DSAR actually needs, pre-written, with the operator's own values
dropped in.

Three rules shape the whole module:

**Templates narrow, they never widen.** Every fragment is `AND`-ed onto whatever
is already in the box. In a DSAR an over-broad search is not merely noisy: it
surfaces third-party data somebody then has to redact, and it inflates the
export volume that bills on E3. A template that quietly widened scope would be
a privacy problem wearing the costume of a convenience.

**The composition is done here, not in the browser.** `A OR B AND C` does not
mean what it looks like, and a template that silently changed the meaning of a
hand-written query would be the worst kind of bug this tool can have — the sort
that returns a plausible number. The existing query is parenthesised before the
fragment is joined to it, and that behaviour is tested.

**The result is a suggestion, not a submission.** Rendering writes into the same
textarea the operator was already editing. Nothing reaches Graph without
passing under their eyes first, which matters more here than for expansion: a
template encodes somebody else's assumption about what a DSAR needs.

Definitions live in `query_templates.json` — data, for the same reason the
capability map is data: the vocabulary in an employment-file sweep is a matter
of judgement and local practice, and correcting it should not mean touching
Python. The *construction* stays in code, because it needs escaping.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# `_date_clause` and `_or_group` are underscored because they are not public
# API of the package — but they are shared within it deliberately. Re-writing
# the date clause here would mean two definitions of "scope by date", and the
# second one would be the one that forgot `lastmodifiedtime`.
from dsar.identity.kql import DateRange, KqlError, _date_clause, _or_group, quote_phrase

__all__ = [
    "QueryTemplate",
    "TemplateInput",
    "load_templates",
    "render_template",
    "compose",
    "TEMPLATES_PATH",
]

log = logging.getLogger(__name__)

TEMPLATES_PATH = Path(__file__).with_name("query_templates.json")

#: A file extension is the one value that reaches a query **unquoted** — KQL
#: `filetype:` takes a bare token. Everything else in this module goes through
#: `quote_phrase`, which refuses anything that could break out of a phrase. This
#: is therefore the injection surface, and it is allowlisted rather than
#: escaped: a real extension is alphanumeric and short, and anything else is a
#: mistake or an attempt.
_FILETYPE = re.compile(r"^[A-Za-z0-9]{1,10}$")

#: `kind:` and similar take a bare token too, but the operator never types one —
#: they pick from `options` in the JSON. Validated anyway, because a definition
#: file is editable and a typo should fail loudly rather than produce a query
#: that parses into something else.
_BARE_TOKEN = re.compile(r"^[a-z][a-z0-9_]{0,30}$")


class TemplateError(ValueError):
    """A template, or the values given to it, cannot produce a query."""


@dataclass(frozen=True)
class TemplateInput:
    name: str
    label: str
    kind: str  # date | text | terms | choice | filetypes
    required: bool = False
    placeholder: str = ""
    help: str = ""
    options: tuple[tuple[str, str], ...] = ()  # (value, label)


@dataclass(frozen=True)
class QueryTemplate:
    id: str
    name: str
    purpose: str
    builder: str
    inputs: tuple[TemplateInput, ...]
    fixed_terms: tuple[str, ...] = ()
    guidance: str = ""
    caution: str = ""
    verified: str = ""
    #: Measured to reduce the site count to zero — the clause is a mail-item
    #: property, so it silently excludes SharePoint and OneDrive. Carried as a
    #: field rather than left to the prose in `caution` because the interface
    #: has to act on it, and a caution inside a collapsed panel is not a control.
    mailbox_only: bool = False


# ---------------------------------------------------------------- loading


def load_templates(path: Path | None = None) -> tuple[QueryTemplate, ...]:
    """Read and validate the definition file.

    Validation is not ceremony. An unknown `builder` would otherwise surface as
    a template that silently produces nothing, and a template that produces
    nothing looks exactly like a search with no results.
    """
    source = path or TEMPLATES_PATH
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TemplateError(f"query templates are unreadable: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("templates"), list):
        raise TemplateError("query templates must be an object with a `templates` list")
    _require_version(raw)

    out: list[QueryTemplate] = []
    seen: set[str] = set()
    for entry in raw["templates"]:
        template = _parse_template(entry)
        if template.id in seen:
            raise TemplateError(f"duplicate template id: {template.id}")
        seen.add(template.id)
        out.append(template)
    return tuple(out)


def _require_version(raw: dict[str, Any]) -> str:
    """The file-level version, required rather than optional.

    The field existed from the start and nothing read it — which is how the
    `attachments` template shipped without a `verified` date: an unread field
    is an optional field whatever the schema says. It is read now because the
    audit trail stamps `template id @ file version` on every application, and
    a version that can silently be absent would stamp records with nothing.
    """
    version = raw.get("version")
    if not isinstance(version, str) or not version.strip():
        raise TemplateError("query templates must carry a top-level `version`")
    return version.strip()


def templates_version(path: Path | None = None) -> str:
    """The version of the template file, for the audit stamp."""
    source = path or TEMPLATES_PATH
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TemplateError(f"query templates are unreadable: {exc}") from exc
    if not isinstance(raw, dict):
        raise TemplateError("query templates must be an object")
    return _require_version(raw)


def _parse_template(entry: Any) -> QueryTemplate:
    if not isinstance(entry, dict):
        raise TemplateError("each template must be an object")
    for key in ("id", "name", "purpose", "builder"):
        if not isinstance(entry.get(key), str) or not entry[key].strip():
            raise TemplateError(f"template is missing a usable {key!r}")
    builder = entry["builder"]
    if builder not in _BUILDERS:
        raise TemplateError(f"template {entry['id']!r} names an unknown builder {builder!r}")

    # `verified` is required: it records when the rendered KQL was last run
    # against a real tenant, and an optional field is how one template shipped
    # without it. A template that has not been run says `"unverified"` — a
    # visible admission, where a fabricated date would be this project's own
    # recurring defect written into its data file.
    verified = entry.get("verified")
    if not isinstance(verified, str) or not verified.strip():
        raise TemplateError(f"template {entry['id']!r} is missing a usable 'verified'")

    inputs = tuple(_parse_input(i, entry["id"]) for i in entry.get("inputs", []))
    fixed = tuple(str(t) for t in entry.get("fixed_terms", []))
    for term in fixed:
        # Fail at load rather than at use: a term that cannot be quoted would
        # otherwise drop out mid-render and quietly narrow the sweep.
        quote_phrase(term)
    return QueryTemplate(
        id=entry["id"],
        name=entry["name"],
        purpose=entry["purpose"],
        builder=builder,
        inputs=inputs,
        fixed_terms=fixed,
        guidance=str(entry.get("guidance") or ""),
        caution=str(entry.get("caution") or ""),
        verified=verified.strip(),
        mailbox_only=bool(entry.get("mailbox_only", False)),
    )


def _parse_input(raw: Any, template_id: str) -> TemplateInput:
    if not isinstance(raw, dict):
        raise TemplateError(f"template {template_id!r} has a malformed input")
    kind = str(raw.get("kind") or "")
    if kind not in ("date", "text", "terms", "choice", "filetypes"):
        raise TemplateError(f"template {template_id!r} has an unknown input kind {kind!r}")
    options: list[tuple[str, str]] = []
    for option in raw.get("options", []):
        value, label = str(option.get("value", "")), str(option.get("label", ""))
        if not _BARE_TOKEN.match(value):
            raise TemplateError(
                f"template {template_id!r} has an unusable option value {value!r}"
            )
        options.append((value, label or value))
    return TemplateInput(
        name=str(raw.get("name") or ""),
        label=str(raw.get("label") or ""),
        kind=kind,
        required=bool(raw.get("required")),
        placeholder=str(raw.get("placeholder") or ""),
        help=str(raw.get("help") or ""),
        options=tuple(options),
    )


# ---------------------------------------------------------------- builders


def _build_date_range(template: QueryTemplate, values: dict[str, Any]) -> str:
    """Reuses the expansion date clause, so mail and files stay in step."""
    dates = DateRange(
        start=_text(values, "start") or None,
        end=_text(values, "end") or None,
    )
    if not dates.is_set:
        raise TemplateError("give at least one date")
    return _date_clause(dates)


def _build_choice(template: QueryTemplate, values: dict[str, Any]) -> str:
    """A fixed property clause chosen from the definition's own options."""
    field = _sole_input(template, "choice")
    chosen = _text(values, field.name)
    allowed = {value for value, _ in field.options}
    if chosen not in allowed:
        raise TemplateError(f"choose one of: {', '.join(sorted(allowed))}")
    return f"{_property_of(template)}:{chosen}"


def _build_phrase_or(template: QueryTemplate, values: dict[str, Any]) -> str:
    """The template's own vocabulary, plus anything the operator adds."""
    terms = list(template.fixed_terms) + _terms(values, "terms")
    clauses = [quote_phrase(term) for term in _dedupe_ci(terms)]
    if not clauses:
        raise TemplateError("no terms to search for")
    return _or_group(clauses)


def _build_people_or(template: QueryTemplate, values: dict[str, Any]) -> str:
    """Addresses become `participants:`; anything else is a free-text mention.

    The split is by shape rather than by asking, because an operator naming the
    other party in a grievance should not have to know which KQL property that
    becomes. A name is a mention; an address is a participant.
    """
    raw = _terms(values, "people")
    if not raw:
        raise TemplateError("name at least one person")
    clauses: list[str] = []
    for value in _dedupe_ci(raw):
        quoted = quote_phrase(value)
        clauses.append(f"participants:{quoted}" if _looks_like_address(value) else quoted)
    return _or_group(clauses)


def _build_flag(template: QueryTemplate, values: dict[str, Any]) -> str:
    """A literal clause with no operator input at all, e.g. `hasattachment:true`."""
    clause = _property_of(template)
    if ":" not in clause:
        raise TemplateError(f"template {template.id!r} has no usable property clause")
    return clause


def _build_filetypes(template: QueryTemplate, values: dict[str, Any]) -> str:
    extensions = _terms(values, "filetypes")
    if not extensions:
        raise TemplateError("name at least one file type")
    clauses = []
    for extension in _dedupe_ci(extensions):
        token = extension.lstrip(".")
        if not _FILETYPE.match(token):
            raise TemplateError(
                f"{extension!r} is not a file extension. Letters and digits only — "
                f"a file type is not quoted in KQL, so it is the one value that "
                f"cannot be made safe by quoting"
            )
        clauses.append(f"filetype:{token.lower()}")
    return _or_group(clauses)


_BUILDERS = {
    "date_range": _build_date_range,
    "choice": _build_choice,
    "phrase_or": _build_phrase_or,
    "people_or": _build_people_or,
    "flag": _build_flag,
    "filetypes": _build_filetypes,
}


# ---------------------------------------------------------------- rendering


def render_template(
    template: QueryTemplate,
    values: dict[str, Any],
    existing: str = "",
) -> str:
    """Produce the new query: the existing one, narrowed by this template.

    Never logs `values`. §11 forbids KQL free-text values in logs, and the
    values here are the most identifying thing in the tool — the other party to
    a grievance, a subject's terms of employment. The template id is logged
    because it is a category, not a person.
    """
    builder = _BUILDERS.get(template.builder)
    if builder is None:  # unreachable via load_templates, kept for direct construction
        raise TemplateError(f"unknown builder {template.builder!r}")
    fragment = builder(template, values)
    log.debug("rendered query template %s", template.id)
    return compose(existing, fragment)


def compose(existing: str, fragment: str) -> str:
    """Join a fragment to an existing query without changing what it meant.

    The parentheses are the whole point. `participants:"a" OR "b"` narrowed by
    `kind:email` is not `participants:"a" OR "b" AND kind:email` — `AND` binds
    tighter, so that reads as "a, or any email mentioning b", which is wider
    than the query it was supposed to narrow and wrong in a way that still
    returns a believable number.
    """
    left = (existing or "").strip()
    right = (fragment or "").strip()
    if not right:
        return left
    if not left:
        return right
    if not _is_atomic(left):
        left = f"({left})"
    if not _is_atomic(right):
        right = f"({right})"
    return f"{left} AND {right}"


def _is_atomic(query: str) -> bool:
    """True when a query needs no parentheses to survive being ANDed.

    Either it is already one balanced parenthesised group, or it contains no
    bare boolean operator to be re-associated. Deliberately conservative:
    a wrong `True` changes the meaning of a query, a wrong `False` adds a
    redundant bracket.
    """
    if _wrapped_in_one_group(query):
        return True
    depth = 0
    for token in re.finditer(r'"[^"]*"|[()]|\b(?:AND|OR|NOT)\b', query):
        text = token.group(0)
        if text == "(":
            depth += 1
        elif text == ")":
            depth -= 1
        elif text in ("AND", "OR", "NOT") and depth == 0:
            return False
    return True


def _wrapped_in_one_group(query: str) -> bool:
    if not (query.startswith("(") and query.endswith(")")):
        return False
    depth = 0
    for index, char in enumerate(query):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and index != len(query) - 1:
                return False  # e.g. "(a) OR (b)" — the outer parens are not one group
    return depth == 0


# ---------------------------------------------------------------- helpers


def _property_of(template: QueryTemplate) -> str:
    """The literal clause or property name carried in `fixed_terms[0]`.

    `choice` and `flag` templates carry their KQL property here rather than in
    the input, because the operator never supplies it and it must not look as
    though they could.
    """
    if not template.fixed_terms:
        raise TemplateError(f"template {template.id!r} declares no property")
    return template.fixed_terms[0]


def _sole_input(template: QueryTemplate, kind: str) -> TemplateInput:
    matches = [i for i in template.inputs if i.kind == kind]
    if len(matches) != 1:
        raise TemplateError(f"template {template.id!r} needs exactly one {kind} input")
    return matches[0]


def _text(values: dict[str, Any], key: str) -> str:
    value = values.get(key)
    return value.strip() if isinstance(value, str) else ""


def _terms(values: dict[str, Any], key: str) -> list[str]:
    """Accept a list, or one string separated by commas or newlines."""
    value = values.get(key)
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [part.strip() for part in re.split(r"[,\n]", value) if part.strip()]
    return []


def _dedupe_ci(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        key = value.lower()
        if key not in seen:
            seen.add(key)
            out.append(value)
    return out


def _looks_like_address(value: str) -> bool:
    return "@" in value and " " not in value.strip()

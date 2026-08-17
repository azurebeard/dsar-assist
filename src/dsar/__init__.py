"""DSAR Assist — a control plane for Microsoft Purview eDiscovery DSAR cases.

It has no data plane. It cannot show you a document and it cannot copy one
anywhere. The app registration requests Microsoft Graph and nothing else — the
separate resource that carries the eDiscovery download permission is never
named in this codebase — and no download or preview call exists in the
permitted-operations table. Both facts are asserted structurally at every
commit, and at every sign-in the granted scopes from the token response are
checked: a download-capable scope refuses the sign-in. (An earlier version of
this docstring said `doctor` performed that check; nothing did, and `doctor`
never could — it has no session and no token.)
"""

from __future__ import annotations

__all__ = ["__version__"]

# Hardcoded rather than read from installed metadata, so the import works the
# same frozen, vendored or in a container — and held to `pyproject.toml` by a
# structural test, because the v0.1.1 tag shipped reporting "dsar 0.1.0": the
# release bump touched pyproject and this line drifted, while the doctor
# "version agreement" check compared this constant against itself.
__version__ = "0.1.1"

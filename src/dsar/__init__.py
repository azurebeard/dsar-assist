"""DSAR Assist — a control plane for Microsoft Purview eDiscovery DSAR cases.

It has no data plane. It cannot show you a document and it cannot copy one
anywhere. The app registration requests Microsoft Graph and nothing else — the
separate resource that carries the eDiscovery download permission is never
named in this codebase — and no download or preview call exists in the
permitted-operations table. Both facts are asserted structurally at every
commit, and `doctor` re-proves the first at runtime by inspecting the issued
token's scopes.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"

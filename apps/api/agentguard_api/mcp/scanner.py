"""Heuristic MCP server checks (PRD §17).

Not a substitute for driving the server; this flags configuration-level risk
from what's registered. Behavioural checks (unexpected network calls) arrive
with the detection service in Step 8.
"""

from __future__ import annotations

import re

from ..models.enums import McpServerStatus, RiskSeverity

_DANGEROUS_FS = re.compile(
    r"(?i)(filesystem|file[_\- ]?system|\bfs\b|read[_\- ]?file|write[_\- ]?file)"
)
_BROAD_SCOPE = {"admin", "write", "execute", "*", "all"}

_ISSUE_SEVERITY = {
    "untrusted_server": RiskSeverity.high,
    "excessive_permissions": RiskSeverity.high,
    "dangerous_filesystem_access": RiskSeverity.high,
    "credential_exposure": RiskSeverity.critical,
    "external_dependencies": RiskSeverity.medium,
    "no_version_pinned": RiskSeverity.low,
}
_RANK = [
    RiskSeverity.info,
    RiskSeverity.low,
    RiskSeverity.medium,
    RiskSeverity.high,
    RiskSeverity.critical,
]


def scan(
    *,
    trusted: bool,
    url: str | None,
    version: str | None,
    permissions: list,
    external_dependencies: list,
    metadata_flags: dict,
) -> dict:
    issues: list[str] = []

    if not trusted:
        issues.append("untrusted_server")
    perms = {str(p).lower() for p in permissions or []}
    if perms & _BROAD_SCOPE:
        issues.append("excessive_permissions")
    if any(_DANGEROUS_FS.search(str(p)) for p in permissions or []):
        issues.append("dangerous_filesystem_access")
    if url and re.search(r"://[^/\s:@]+:[^/\s:@]+@", url):
        issues.append("credential_exposure")
    if external_dependencies:
        issues.append("external_dependencies")
    if not version:
        issues.append("no_version_pinned")
    if metadata_flags.get("tool_poisoning") or metadata_flags.get("malicious_metadata"):
        issues.append("malicious_metadata")

    severity = RiskSeverity.info
    for issue in issues:
        sev = _ISSUE_SEVERITY.get(issue, RiskSeverity.medium)
        if _RANK.index(sev) > _RANK.index(severity):
            severity = sev

    if "credential_exposure" in issues or (not trusted and severity == RiskSeverity.high):
        server_status = McpServerStatus.quarantined
    elif issues:
        server_status = McpServerStatus.review_required
    else:
        server_status = McpServerStatus.active

    checks = {
        name: (name not in issues)
        for name in [
            "untrusted_server",
            "excessive_permissions",
            "dangerous_filesystem_access",
            "credential_exposure",
            "external_dependencies",
            "no_version_pinned",
        ]
    }
    return {
        "issues": issues,
        "checks": checks,
        "severity": severity.value,
        "status": server_status.value,
    }

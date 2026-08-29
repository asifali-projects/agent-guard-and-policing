"""Apply the runtime's redaction paths to a parameter dict."""

from __future__ import annotations

import copy
import re

REDACTED = "[REDACTED]"
_INDEX = re.compile(r"\[(\d+)\]")


def _tokens(path: str) -> list[str | int]:
    # "parameters.user.contacts[0].email" -> ["user", "contacts", 0, "email"]
    body = path.split(".", 1)[1] if path.startswith("parameters.") else path
    out: list[str | int] = []
    for part in body.split("."):
        m = _INDEX.search(part)
        name = _INDEX.sub("", part)
        if name:
            out.append(name)
        if m:
            out.append(int(m.group(1)))
    return out


def redact_params(parameters: dict, paths: list[str]) -> dict:
    """Return a deep copy of ``parameters`` with every ``path`` leaf masked."""
    result = copy.deepcopy(parameters)
    for path in paths:
        tokens = _tokens(path)
        if not tokens:
            continue
        node = result
        try:
            for key in tokens[:-1]:
                node = node[key]
            node[tokens[-1]] = REDACTED
        except (KeyError, IndexError, TypeError):
            continue
    return result

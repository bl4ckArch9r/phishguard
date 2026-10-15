"""Shared evidence record produced by every analysis layer."""
from __future__ import annotations

from dataclasses import asdict, dataclass

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Evidence:
    layer: str          # url | model | page | domain | intel | brand
    id: str             # stable identifier, useful for tests/reports
    title: str          # short, plain-language finding
    detail: str = ""    # one sentence of context
    severity: str = "info"
    points: int = 0     # contribution to the risk score (0 for info / reassuring)

    def to_dict(self):
        return asdict(self)

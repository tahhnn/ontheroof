"""Nap va kiem tra dinh nghia rule tuong quan tu file YAML."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

import yaml

log = logging.getLogger(__name__)

VALID_TYPES = {"threshold", "distinct", "sequence"}
VALID_SEVERITY = {"low", "medium", "high", "critical"}


@dataclass
class Stage:
    name: str
    filter: dict[str, Any]
    min_count: int = 1


@dataclass
class CorrelationRule:
    id: str
    name: str
    type: str
    severity: str
    window: int
    summary: str
    description: str = ""
    group_by: str | None = None
    join_field: str | None = None
    filter: dict[str, Any] = field(default_factory=dict)
    min_count: int = 1
    distinct_field: str | None = None
    min_cardinality: int = 2
    stages: list[Stage] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if self.type not in VALID_TYPES:
            raise ValueError(f"rule {self.id}: type '{self.type}' khong hop le")
        if self.severity not in VALID_SEVERITY:
            raise ValueError(f"rule {self.id}: severity '{self.severity}' khong hop le")
        if self.window <= 0:
            raise ValueError(f"rule {self.id}: window phai > 0")
        if self.type in {"threshold", "distinct"} and not self.group_by:
            raise ValueError(f"rule {self.id}: thieu group_by")
        if self.type == "distinct" and not self.distinct_field:
            raise ValueError(f"rule {self.id}: thieu distinct_field")
        if self.type == "sequence":
            if not self.join_field:
                raise ValueError(f"rule {self.id}: thieu join_field")
            if len(self.stages) < 2:
                raise ValueError(f"rule {self.id}: sequence can it nhat 2 stage")


def _parse_rule(raw: dict[str, Any]) -> CorrelationRule:
    stages = [Stage(**s) for s in raw.pop("stages", [])]
    rule = CorrelationRule(stages=stages, **raw)
    rule.validate()
    return rule


def load_rules(path: str) -> list[CorrelationRule]:
    """Nap tat ca file .yml/.yaml trong thu muc; bo qua file loi va ghi log."""
    rules: list[CorrelationRule] = []
    if not os.path.isdir(path):
        log.error("Thu muc rule khong ton tai: %s", path)
        return rules

    for fname in sorted(os.listdir(path)):
        if not fname.endswith((".yml", ".yaml")):
            continue
        full = os.path.join(path, fname)
        try:
            with open(full, encoding="utf-8") as fh:
                payload = yaml.safe_load(fh) or []
            for raw in payload:
                rules.append(_parse_rule(raw))
        except Exception as exc:  # file loi khong duoc lam chet engine
            log.error("Bo qua %s: %s", fname, exc)

    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"Trung rule id: {sorted(dupes)}")

    log.info("Nap %d rule tuong quan tu %s", len(rules), path)
    return rules

"""Engine tuong quan: dich rule YAML thanh query OpenSearch va sinh finding.

Ba kieu rule:
  threshold - dem so alert khop filter theo tung khoa (group_by) trong cua so.
  distinct  - dem so gia tri KHAC NHAU cua mot truong theo tung khoa.
  sequence  - nhieu giai doan phai xay ra DUNG THU TU tren cung mot khoa join.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .indexer import IndexerClient
from .rules import CorrelationRule, Stage

log = logging.getLogger(__name__)

MAX_BUCKETS = 500


@dataclass
class Finding:
    rule: CorrelationRule
    key: str
    window_start: datetime
    window_end: datetime
    count: int
    evidence: dict[str, Any] = field(default_factory=dict)
    first_seen: datetime | None = None  # su kien som nhat trong finding

    @property
    def anchor(self) -> datetime:
        """Moc thoi gian cua su kien, khong phai cua lan quet."""
        return self.first_seen or self.window_end

    @property
    def doc_id(self) -> str:
        """_id tat dinh theo thoi diem su kien.

        Neo theo window_end (gio quet) se sinh _id moi moi khi cua so truot qua moc
        chia o -> mot vu tan cong ra 2 alert. Neo theo first_seen thi cac lan quet
        sau van thay cung su kien som nhat -> cung _id -> ghi de.
        """
        bucket = int(self.anchor.timestamp()) // max(self.rule.window, 1)
        raw = f"{self.rule.id}|{self.key}|{bucket}"
        return hashlib.sha1(raw.encode()).hexdigest()

    def to_document(self) -> dict[str, Any]:
        return {
            "@timestamp": self.window_end.isoformat(),
            "correlation_rule": self.rule.id,
            "rule_name": self.rule.name,
            "severity": self.rule.severity,
            "summary": self.rule.summary.format(key=self.key, count=self.count),
            "description": self.rule.description,
            "entity": self.key,
            "entity_field": self.rule.group_by or self.rule.join_field,
            "event_count": self.count,
            "window_seconds": self.rule.window,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "mitre_ids": self.rule.mitre,
            "evidence": self.evidence,
            "source": "siem-correlator",
        }


def _clause(field_name: str, value: Any) -> dict[str, Any]:
    """Dich mot cap field/value trong YAML thanh menh de query."""
    for suffix, op in (("__gte", "gte"), ("__lte", "lte"), ("__gt", "gt"), ("__lt", "lt")):
        if field_name.endswith(suffix):
            return {"range": {field_name[: -len(suffix)]: {op: value}}}
    if isinstance(value, list):
        return {"terms": {field_name: [str(v) for v in value]}}
    if isinstance(value, str) and ("*" in value or "?" in value):
        return {"wildcard": {field_name: value}}
    return {"term": {field_name: value}}


def build_filter(filters: dict[str, Any]) -> list[dict[str, Any]]:
    return [_clause(k, v) for k, v in filters.items()]


def _ms_to_dt(value: float | None) -> datetime | None:
    return datetime.fromtimestamp(value / 1000, timezone.utc) if value else None


def _time_range(start: datetime, end: datetime) -> dict[str, Any]:
    return {"range": {"@timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}}


class CorrelationEngine:
    def __init__(self, client: IndexerClient, alerts_index: str):
        self.client = client
        self.alerts_index = alerts_index

    # ---------- threshold ----------
    def _run_threshold(self, rule: CorrelationRule, start: datetime, end: datetime) -> list[Finding]:
        body = {
            "size": 0,
            "query": {"bool": {"filter": build_filter(rule.filter) + [_time_range(start, end)]}},
            "aggs": {
                "keys": {
                    "terms": {
                        "field": rule.group_by,
                        "size": MAX_BUCKETS,
                        "min_doc_count": rule.min_count,
                    },
                    "aggs": {
                        "first_seen": {"min": {"field": "@timestamp"}},
                        "sample": {
                            "top_hits": {
                                "size": 3,
                                "_source": ["rule.id", "rule.description", "agent.name"],
                            }
                        }
                    },
                }
            },
        }
        res = self.client.search(self.alerts_index, body)
        findings = []
        for bucket in res.get("aggregations", {}).get("keys", {}).get("buckets", []):
            hits = bucket["sample"]["hits"]["hits"]
            findings.append(
                Finding(
                    rule=rule,
                    key=str(bucket["key"]),
                    window_start=start,
                    window_end=end,
                    count=bucket["doc_count"],
                    evidence={"sample_alerts": [h["_source"] for h in hits]},
                    first_seen=_ms_to_dt(bucket.get("first_seen", {}).get("value")),
                )
            )
        return findings

    # ---------- distinct ----------
    def _run_distinct(self, rule: CorrelationRule, start: datetime, end: datetime) -> list[Finding]:
        body = {
            "size": 0,
            "query": {"bool": {"filter": build_filter(rule.filter) + [_time_range(start, end)]}},
            "aggs": {
                "keys": {
                    "terms": {"field": rule.group_by, "size": MAX_BUCKETS},
                    "aggs": {
                        "first_seen": {"min": {"field": "@timestamp"}},
                        "values": {"terms": {"field": rule.distinct_field, "size": 50}},
                    },
                }
            },
        }
        res = self.client.search(self.alerts_index, body)
        findings = []
        for bucket in res.get("aggregations", {}).get("keys", {}).get("buckets", []):
            values = [b["key"] for b in bucket["values"]["buckets"]]
            if len(values) < rule.min_cardinality:
                continue
            findings.append(
                Finding(
                    rule=rule,
                    key=str(bucket["key"]),
                    window_start=start,
                    window_end=end,
                    count=bucket["doc_count"],
                    evidence={"distinct_values": values, "distinct_count": len(values)},
                    first_seen=_ms_to_dt(bucket.get("first_seen", {}).get("value")),
                )
            )
        return findings

    # ---------- sequence ----------
    def _stage_buckets(
        self, rule: CorrelationRule, stage: Stage, start: datetime, end: datetime
    ) -> dict[str, dict[str, Any]]:
        body = {
            "size": 0,
            "query": {"bool": {"filter": build_filter(stage.filter) + [_time_range(start, end)]}},
            "aggs": {
                "keys": {
                    "terms": {
                        "field": rule.join_field,
                        "size": MAX_BUCKETS,
                        "min_doc_count": stage.min_count,
                    },
                    "aggs": {
                        "first_seen": {"min": {"field": "@timestamp"}},
                        "last_seen": {"max": {"field": "@timestamp"}},
                    },
                }
            },
        }
        res = self.client.search(self.alerts_index, body)
        out: dict[str, dict[str, Any]] = {}
        for b in res.get("aggregations", {}).get("keys", {}).get("buckets", []):
            out[str(b["key"])] = {
                "count": b["doc_count"],
                "first": b["first_seen"]["value"] or 0.0,
                "last": b["last_seen"]["value"] or 0.0,
            }
        return out

    def _run_sequence(self, rule: CorrelationRule, start: datetime, end: datetime) -> list[Finding]:
        per_stage = [self._stage_buckets(rule, s, start, end) for s in rule.stages]

        # Khoa phai xuat hien o MOI giai doan
        common = set(per_stage[0])
        for buckets in per_stage[1:]:
            common &= set(buckets)

        findings = []
        for key in sorted(common):
            timeline = [buckets[key] for buckets in per_stage]
            # Thu tu thoi gian: giai doan truoc phai bat dau truoc khi giai doan sau ket thuc
            ordered = all(
                timeline[i]["first"] <= timeline[i + 1]["last"] for i in range(len(timeline) - 1)
            )
            if not ordered:
                continue
            findings.append(
                Finding(
                    rule=rule,
                    key=key,
                    window_start=start,
                    window_end=end,
                    count=sum(t["count"] for t in timeline),
                    first_seen=_ms_to_dt(timeline[0]["first"]),
                    evidence={
                        "stages": [
                            {
                                "name": stage.name,
                                "count": t["count"],
                                "first_seen": datetime.fromtimestamp(
                                    t["first"] / 1000, timezone.utc
                                ).isoformat(),
                                "last_seen": datetime.fromtimestamp(
                                    t["last"] / 1000, timezone.utc
                                ).isoformat(),
                            }
                            for stage, t in zip(rule.stages, timeline)
                        ]
                    },
                )
            )
        return findings

    # ---------- entrypoint ----------
    def run(self, rule: CorrelationRule, now: datetime | None = None) -> list[Finding]:
        end = now or datetime.now(timezone.utc)
        start = end - timedelta(seconds=rule.window)
        runner = {
            "threshold": self._run_threshold,
            "distinct": self._run_distinct,
            "sequence": self._run_sequence,
        }[rule.type]
        try:
            findings = runner(rule, start, end)
        except Exception as exc:
            log.error("Rule '%s' loi khi chay: %s", rule.id, exc)
            return []
        if findings:
            log.info("Rule '%s': %d finding", rule.id, len(findings))
        return findings

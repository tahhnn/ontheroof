"""Test engine tuong quan bang du lieu gia - khong can Indexer that.

Chay:  python -m pytest correlation/tests -q
Hoac:  python correlation/tests/test_engine.py
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from siem_correlator.engine import CorrelationEngine, build_filter  # noqa: E402
from siem_correlator.rules import load_rules  # noqa: E402

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")


class FakeIndexer:
    """Tra ve ket qua agg dung theo thu tu cac lan search duoc goi."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.bodies = []

    def search(self, index, body):
        self.bodies.append(body)
        return self.responses.pop(0)


def _terms(buckets):
    return {"aggregations": {"keys": {"buckets": buckets}}}


def test_load_rules():
    rules = load_rules(RULES_DIR)
    assert rules, "phai nap duoc it nhat 1 rule"
    ids = {r.id for r in rules}
    assert "brute_force_then_success" in ids
    print(f"[OK] nap {len(rules)} rule")


def test_build_filter_range_suffix():
    clauses = build_filter({"rule.level__gte": 10, "rule.id": ["100110", "100111"]})
    assert {"range": {"rule.level": {"gte": 10}}} in clauses
    assert {"terms": {"rule.id": ["100110", "100111"]}} in clauses
    print("[OK] build_filter dich dung range va terms")


def test_threshold():
    rules = {r.id: r for r in load_rules(RULES_DIR)}
    rule = rules["mass_data_export_by_user"]
    empty_hits = {"hits": {"hits": []}}
    fake = FakeIndexer(
        [
            _terms(
                [
                    {"key": "nvhung", "doc_count": 7, "sample": empty_hits},
                    {"key": "ketoan1", "doc_count": 6, "sample": empty_hits},
                ]
            )
        ]
    )
    engine = CorrelationEngine(fake, "wazuh-alerts-*")
    findings = engine.run(rule, now=datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc))
    assert len(findings) == 2
    assert findings[0].key == "nvhung"
    assert "7 lan" in findings[0].to_document()["summary"]
    # min_doc_count phai duoc day xuong query, khong loc o phia client
    assert fake.bodies[0]["aggs"]["keys"]["terms"]["min_doc_count"] == 5
    print("[OK] threshold sinh finding va day min_doc_count xuong Indexer")


def test_distinct_respects_cardinality():
    rules = {r.id: r for r in load_rules(RULES_DIR)}
    rule = rules["impossible_travel"]  # min_cardinality = 3
    fake = FakeIndexer(
        [
            _terms(
                [
                    {
                        "key": "nvhung",
                        "doc_count": 5,
                        "values": {"buckets": [{"key": "10.0.0.1"}, {"key": "10.0.0.2"}, {"key": "1.2.3.4"}]},
                    },
                    {
                        "key": "ketoan1",
                        "doc_count": 4,
                        "values": {"buckets": [{"key": "10.0.0.9"}, {"key": "10.0.0.8"}]},
                    },
                ]
            )
        ]
    )
    engine = CorrelationEngine(fake, "wazuh-alerts-*")
    findings = engine.run(rule)
    assert [f.key for f in findings] == ["nvhung"], "ketoan1 chi co 2 IP nen phai bi loai"
    print("[OK] distinct ton trong min_cardinality")


def test_sequence_order():
    rules = {r.id: r for r in load_rules(RULES_DIR)}
    rule = rules["brute_force_then_success"]  # 2 stage, join theo data.srcip

    def bucket(key, first_ms, last_ms, count=1):
        return {
            "key": key,
            "doc_count": count,
            "first_seen": {"value": first_ms},
            "last_seen": {"value": last_ms},
        }

    t0 = 1_756_000_000_000
    fake = FakeIndexer(
        [
            # stage 1: do mat khau
            _terms([bucket("1.2.3.4", t0, t0 + 60_000, 9), bucket("5.6.7.8", t0 + 500_000, t0 + 600_000, 9)]),
            # stage 2: dang nhap thanh cong (5.6.7.8 thanh cong TRUOC khi do -> phai loai)
            _terms([bucket("1.2.3.4", t0 + 90_000, t0 + 90_000), bucket("5.6.7.8", t0, t0)]),
        ]
    )
    engine = CorrelationEngine(fake, "wazuh-alerts-*")
    findings = engine.run(rule)
    assert [f.key for f in findings] == ["1.2.3.4"]
    doc = findings[0].to_document()
    assert doc["severity"] == "critical"
    assert len(doc["evidence"]["stages"]) == 2
    print("[OK] sequence chi giu chuoi dung thu tu thoi gian")


def test_doc_id_stable():
    rules = {r.id: r for r in load_rules(RULES_DIR)}
    rule = rules["mass_data_export_by_user"]
    empty_hits = {"hits": {"hits": []}}
    now = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
    ids = []
    for _ in range(2):
        fake = FakeIndexer([_terms([{"key": "nvhung", "doc_count": 7, "sample": empty_hits}])])
        ids.append(CorrelationEngine(fake, "wazuh-alerts-*").run(rule, now=now)[0].doc_id)
    assert ids[0] == ids[1], "chay lai cung cua so phai ra cung _id de khong nhan ban alert"
    print("[OK] doc_id tat dinh")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nTat ca test da qua.")

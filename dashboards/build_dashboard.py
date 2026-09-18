#!/usr/bin/env python3
"""Sinh file NDJSON saved-objects cho dashboard "SIEM-raw - Alert tuong quan".

Viet dashboard bang script thay vi go tay JSON de de sua va de giai thich trong
bao cao. Chay:

    python dashboards/build_dashboard.py

Ket qua: dashboards/siem-correlated-dashboard.ndjson
Import: Wazuh Dashboard > Dashboards Management > Saved objects > Import.
"""

from __future__ import annotations

import json
import os

INDEX_PATTERN_ID = "siem-correlated-index-pattern"
INDEX_PATTERN_TITLE = "siem-correlated-*"
DASHBOARD_ID = "siem-raw-correlation-dashboard"

OUT = os.path.join(os.path.dirname(__file__), "siem-correlated-dashboard.ndjson")


def search_source(query: str = "") -> str:
    return json.dumps(
        {
            "query": {"query": query, "language": "kuery"},
            "filter": [],
            "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        }
    )


def viz(vis_id: str, title: str, vis_state: dict, query: str = "") -> dict:
    return {
        "id": vis_id,
        "type": "visualization",
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
        },
        "references": [
            {
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern",
                "id": INDEX_PATTERN_ID,
            }
        ],
        "migrationVersion": {"visualization": "7.10.0"},
    }


def terms_agg(agg_id: int, field: str, size: int, order_by: str = "1") -> dict:
    return {
        "id": str(agg_id),
        "enabled": True,
        "type": "terms",
        "schema": "segment",
        "params": {
            "field": field,
            "size": size,
            "order": "desc",
            "orderBy": order_by,
            "otherBucket": False,
            "missingBucket": False,
        },
    }


COUNT_AGG = {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}


VISUALIZATIONS = [
    viz(
        "siem-corr-total",
        "Tong so alert tuong quan",
        {
            "title": "Tong so alert tuong quan",
            "type": "metric",
            "aggs": [COUNT_AGG],
            "params": {
                "metric": {
                    "percentageMode": False,
                    "colorSchema": "Green to Red",
                    "metricColorMode": "None",
                    "style": {"fontSize": 48},
                }
            },
        },
    ),
    viz(
        "siem-corr-by-severity",
        "Alert tuong quan theo muc do",
        {
            "title": "Alert tuong quan theo muc do",
            "type": "pie",
            "aggs": [COUNT_AGG, terms_agg(2, "severity", 5)],
            "params": {"type": "pie", "addTooltip": True, "addLegend": True, "isDonut": True},
        },
    ),
    viz(
        "siem-corr-timeline",
        "Alert tuong quan theo thoi gian",
        {
            "title": "Alert tuong quan theo thoi gian",
            "type": "histogram",
            "aggs": [
                COUNT_AGG,
                {
                    "id": "2",
                    "enabled": True,
                    "type": "date_histogram",
                    "schema": "segment",
                    "params": {"field": "@timestamp", "interval": "auto", "min_doc_count": 1},
                },
                {
                    "id": "3",
                    "enabled": True,
                    "type": "terms",
                    "schema": "group",
                    "params": {"field": "severity", "size": 5, "order": "desc", "orderBy": "1"},
                },
            ],
            "params": {"type": "histogram", "addLegend": True, "addTimeMarker": False},
        },
    ),
    viz(
        "siem-corr-top-rules",
        "Rule tuong quan kich hoat nhieu nhat",
        {
            "title": "Rule tuong quan kich hoat nhieu nhat",
            "type": "table",
            "aggs": [COUNT_AGG, terms_agg(2, "correlation_rule", 10)],
            "params": {"perPage": 10, "showPartialRows": False, "showTotal": False},
        },
    ),
    viz(
        "siem-corr-top-entities",
        "Doi tuong bi canh bao nhieu nhat (IP / tai khoan / may)",
        {
            "title": "Doi tuong bi canh bao nhieu nhat",
            "type": "table",
            "aggs": [COUNT_AGG, terms_agg(2, "entity", 15)],
            "params": {"perPage": 10, "showPartialRows": False, "showTotal": False},
        },
    ),
    viz(
        "siem-corr-critical",
        "Alert muc critical",
        {
            "title": "Alert muc critical",
            "type": "table",
            "aggs": [COUNT_AGG, terms_agg(2, "entity", 10)],
            "params": {"perPage": 10, "showPartialRows": False, "showTotal": False},
        },
        query="severity: critical",
    ),
]


# Luoi 48 cot cua OpenSearch Dashboards
PANEL_LAYOUT = [
    ("siem-corr-total", 0, 0, 12, 10),
    ("siem-corr-by-severity", 12, 0, 18, 10),
    ("siem-corr-critical", 30, 0, 18, 10),
    ("siem-corr-timeline", 0, 10, 48, 12),
    ("siem-corr-top-rules", 0, 22, 24, 13),
    ("siem-corr-top-entities", 24, 22, 24, 13),
]


def build_dashboard() -> dict:
    panels = []
    references = []
    for i, (vis_id, x, y, w, h) in enumerate(PANEL_LAYOUT, 1):
        panel_ref = f"panel_{i}"
        panels.append(
            {
                "version": "2.13.0",
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
                "panelIndex": str(i),
                "embeddableConfig": {},
                "panelRefName": panel_ref,
            }
        )
        references.append({"name": panel_ref, "type": "visualization", "id": vis_id})

    return {
        "id": DASHBOARD_ID,
        "type": "dashboard",
        "attributes": {
            "title": "SIEM-raw - Alert tuong quan",
            "description": "Alert do script correlation sinh ra tu index siem-correlated-*",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "version": 1,
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-24h",
            "refreshInterval": {"pause": False, "value": 60000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            },
        },
        "references": references,
        "migrationVersion": {"dashboard": "7.10.0"},
    }


INDEX_PATTERN = {
    "id": INDEX_PATTERN_ID,
    "type": "index-pattern",
    "attributes": {"title": INDEX_PATTERN_TITLE, "timeFieldName": "@timestamp"},
    "references": [],
    "migrationVersion": {"index-pattern": "7.6.0"},
}


def main() -> None:
    objects = [INDEX_PATTERN, *VISUALIZATIONS, build_dashboard()]
    with open(OUT, "w", encoding="utf-8") as fh:
        for obj in objects:
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
        fh.write(json.dumps({"exportedCount": len(objects), "missingRefCount": 0, "missingReferences": []}) + "\n")
    print(f"Da ghi {len(objects)} saved object -> {OUT}")


if __name__ == "__main__":
    main()

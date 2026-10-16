#!/usr/bin/env python3
"""Bien data/results/health.log thanh bieu do + so lieu do on dinh (chuong 5.4).

health.log do scripts/health_snapshot.sh sinh, cron 30 phut/lan, moi dong:
    ts=... disk=37% mem_mb=used/total heap_pct=.. agents_active=.. app_logger=..
    alerts=.. correlated=.. containers=name:status:restartcount,...
Gia tri loi la NA hoac rong -> coi la thieu so lieu, khong lam hong ca dong.

    python scripts/plot_health.py                      # doc log mac dinh, ghi PNG
    python scripts/plot_health.py --log x.log --out x.png
    python scripts/plot_health.py --selftest           # log gia 2 ngay, assert

Can matplotlib de ve PNG (pip install matplotlib); thieu thi van in bang tom tat.
"""
import argparse
import os
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta

INTERVAL_S = 1800        # cron */30
GAP_S = 1.5 * INTERVAL_S  # khoang trong lon hon muc nay = mat diem do (VPS/cron chet)


def num(v):
    """'37%' -> 37.0, 'NA'/'' -> None."""
    v = (v or "").rstrip("%")
    try:
        return float(v)
    except ValueError:
        return None


def parse_line(line):
    kv = dict(p.split("=", 1) for p in line.split() if "=" in p)
    if "ts" not in kv:
        return None
    try:
        ts = datetime.fromisoformat(kv["ts"])
    except ValueError:
        return None
    used, _, total = kv.get("mem_mb", "").partition("/")
    containers = {}
    for c in kv.get("containers", "").split(","):
        parts = c.rsplit(":", 2)
        if len(parts) == 3 and num(parts[2]) is not None:
            containers[parts[0]] = (parts[1], int(num(parts[2])))
    return {
        "ts": ts,
        "disk": num(kv.get("disk")),
        "mem_used": num(used),
        "mem_total": num(total),
        "heap": num(kv.get("heap_pct")),
        "agents": num(kv.get("agents_active")),
        "app_logger": num(kv.get("app_logger")),
        "alerts": num(kv.get("alerts")),
        "correlated": num(kv.get("correlated")),
        "containers": containers,
    }


def parse(lines):
    rows = [r for r in map(parse_line, lines) if r]
    return sorted(rows, key=lambda r: r["ts"])


def intervals(rows, bad):
    """Gom cac diem lien tiep thoa bad(row) thanh khoang [(start, end, so_diem)]."""
    out, cur = [], None
    for r in rows:
        if bad(r):
            cur = [r["ts"], r["ts"], 1] if cur is None else [cur[0], r["ts"], cur[2] + 1]
        elif cur:
            out.append(tuple(cur))
            cur = None
    if cur:
        out.append(tuple(cur))
    return out


def alerts_per_day(rows):
    """Cong cac buoc tang giua 2 diem lien tiep vao ngay cua diem sau.
    Buoc am (index bi xoa theo ILM) bo qua de khong ra so am."""
    per_day, prev = defaultdict(float), None
    for r in rows:
        if r["alerts"] is None:
            continue
        if prev is not None and r["alerts"] >= prev:
            per_day[r["ts"].date()] += r["alerts"] - prev
        prev = r["alerts"]
    return dict(sorted(per_day.items()))


def summarize(rows):
    first, last = rows[0]["ts"], rows[-1]["ts"]
    span = (last - first).total_seconds()
    # ky vong = 48 diem/ngay x so ngay, +1 vi n diem phu n-1 khoang
    expected = int(span // INTERVAL_S) + 1
    gaps = [(a["ts"], b["ts"]) for a, b in zip(rows, rows[1:])
            if (b["ts"] - a["ts"]).total_seconds() > GAP_S]

    # app_logger NA = docker exec erp01 that bai -> cung tinh la mat log nen
    applog_down = intervals(rows, lambda r: not r["app_logger"])
    agent_max = max((r["agents"] for r in rows if r["agents"] is not None), default=None)
    agents_drop = intervals(rows, lambda r: r["agents"] is not None and r["agents"] < agent_max)

    restarts, seen = [], {}
    for r in rows:
        for name, (_, rc) in r["containers"].items():
            if name in seen and rc > seen[name]:
                restarts.append((r["ts"], name, seen[name], rc))
            seen[name] = rc

    return {
        "first": first, "last": last, "days": span / 86400,
        "rows": len(rows), "expected": expected,
        "availability": len(rows) / expected,
        "gaps": gaps, "applog_down": applog_down,
        "agent_max": agent_max, "agents_drop": agents_drop,
        "restarts": restarts, "alerts_per_day": alerts_per_day(rows),
    }


def print_summary(s):
    f = "%Y-%m-%d %H:%M"
    print(f"Khoang do      : {s['first']:{f}} -> {s['last']:{f}} ({s['days']:.2f} ngay)")
    print(f"So diem do     : {s['rows']} / {s['expected']} ky vong (48/ngay)")
    print(f"Do san sang    : {s['availability']:.2%}")
    print(f"Mat diem (>45p): {len(s['gaps'])}")
    for a, b in s["gaps"]:
        print(f"  {a:{f}} -> {b:{f}}")
    print(f"app_logger=0/NA: {len(s['applog_down'])} khoang")
    for a, b, n in s["applog_down"]:
        print(f"  {a:{f}} -> {b:{f}} ({n} diem)")
    print(f"agents < {s['agent_max']:.0f}    : {len(s['agents_drop'])} khoang" if s["agent_max"] is not None
          else "agents         : NA toan bo")
    for a, b, n in s["agents_drop"]:
        print(f"  {a:{f}} -> {b:{f}} ({n} diem)")
    print(f"Restart tang   : {len(s['restarts'])} lan")
    for ts, name, old, new in s["restarts"]:
        print(f"  {ts:{f}} {name}: {old} -> {new}")
    apd = list(s["alerts_per_day"].values())
    if apd:
        print(f"Alert/ngay     : TB {sum(apd) / len(apd):.0f}, min {min(apd):.0f}, max {max(apd):.0f}")


def plot(rows, s, out):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("Thieu matplotlib -> bo qua PNG (pip install matplotlib)", file=sys.stderr)
        return False
    nan = float("nan")
    col = lambda k: [nan if r[k] is None else r[k] for r in rows]  # NaN -> dut net, khong ve sai
    ts = [r["ts"] for r in rows]

    fig, ax = plt.subplots(5, 1, figsize=(11, 13), sharex=True)
    ax[0].plot(ts, col("mem_used"), label="RAM used")
    ax[0].plot(ts, col("mem_total"), "--", color="gray", label="RAM total")
    ax[0].set_ylabel("MB")
    ax[1].plot(ts, col("heap"), color="tab:orange")
    ax[1].set_ylabel("Indexer heap %")
    ax[2].plot(ts, col("disk"), color="tab:green")
    ax[2].set_ylabel("Disk / %")
    ax[3].plot(ts, col("alerts"), label="wazuh-alerts")
    ax[3].plot(ts, col("correlated"), label="siem-correlated")
    ax[3].set_ylabel("Alert tich luy")
    days = list(s["alerts_per_day"])
    ax[4].bar([datetime.combine(d, datetime.min.time(), ts[0].tzinfo) + timedelta(hours=12) for d in days],
              list(s["alerts_per_day"].values()), width=0.8)
    ax[4].set_ylabel("Alert / ngay")
    # to vung app_logger chet tren moi truc de doi chieu
    for a, b, _ in s["applog_down"]:
        for x in ax:
            x.axvspan(a, b + timedelta(seconds=INTERVAL_S), color="red", alpha=0.15)
    for x in ax:
        x.grid(alpha=0.3)
    ax[0].legend(loc="upper left")
    ax[3].legend(loc="upper left")
    ax[0].set_title(f"health.log {s['days']:.1f} ngay, san sang {s['availability']:.1%} "
                    f"(vung do = app_logger 0/NA)")
    fig.autofmt_xdate()
    fig.tight_layout()
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    fig.savefig(out, dpi=120)
    plt.close(fig)
    print(f"Da ghi {out}")
    return True


def fake_log(start):
    """2 ngay = 96 diem; app_logger=0 diem 20-25, wazuh.manager restart o diem 60,
    agents 3 -> 2 diem 70-72, heap NA diem 40."""
    lines = []
    for i in range(96):
        ts = start + timedelta(seconds=i * INTERVAL_S)
        rc = 1 if i >= 60 else 0
        lines.append(
            f"ts={ts.isoformat()} disk={30 + i // 20}% mem_mb={5000 + i * 10}/7900 "
            f"heap_pct={'NA' if i == 40 else 40 + i % 15} agents_active={2 if 70 <= i <= 72 else 3} "
            f"app_logger={0 if 20 <= i <= 25 else 1} alerts={1000 + i * 50} correlated={i} "
            f"containers=siem-raw-wazuh.manager-1:running:{rc},erp01:running:0")
    return lines


def selftest():
    from datetime import timezone
    start = datetime(2026, 11, 1, tzinfo=timezone(timedelta(hours=7)))
    at = lambda i: start + timedelta(seconds=i * INTERVAL_S)
    lines = fake_log(start)
    lines.insert(10, "rac khong co ts")  # dong hong phai bi bo qua
    rows = parse(lines)
    s = summarize(rows)
    print_summary(s)

    assert s["rows"] == 96 and s["expected"] == 96 and s["availability"] == 1.0, s
    assert s["gaps"] == []
    assert s["applog_down"] == [(at(20), at(25), 6)], s["applog_down"]
    assert s["restarts"] == [(at(60), "siem-raw-wazuh.manager-1", 0, 1)], s["restarts"]
    assert s["agents_drop"] == [(at(70), at(72), 3)], s["agents_drop"]
    assert rows[40]["heap"] is None
    assert sum(s["alerts_per_day"].values()) == 95 * 50

    # bo 4 diem -> mat 1 khoang, do san sang giam
    s2 = summarize(parse(lines[:50] + lines[54:]))
    assert len(s2["gaps"]) == 1 and s2["rows"] == 92 and s2["expected"] == 96, s2

    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "health.png")
        if plot(rows, s, out):
            assert os.path.getsize(out) > 10_000
    print("SELFTEST OK")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", default="data/results/health.log")
    ap.add_argument("--out", default="data/results/health.png")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    with open(a.log, encoding="utf-8") as fh:
        rows = parse(fh)
    if not rows:
        sys.exit(f"{a.log}: khong co dong hop le")
    s = summarize(rows)
    print_summary(s)
    plot(rows, s, a.out)


if __name__ == "__main__":
    main()

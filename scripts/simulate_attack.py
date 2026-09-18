#!/usr/bin/env python3
"""Sinh log tan cong gia lap gui vao Wazuh manager qua syslog UDP - dung de demo.

Log gia lap den tu hai nguon:
  - Ung dung ERP noi bo (tag "erpapp", host erp01) -> decoder tu viet trong custom/
  - Firewall/router (tag "kernel", host fw01, dinh dang iptables) -> decoder co san cua Wazuh

Vi du:
    python scripts/simulate_attack.py --host 127.0.0.1 --scenario full
    python scripts/simulate_attack.py --scenario portscan --delay 0.2
    python scripts/simulate_attack.py --scenario all --print-only

LUU Y ve --delay: cac rule tan suat cua Wazuh co cua so thoi gian co dinh
(brute force 6 lan/120s, quet cong 15 lan/60s). De --delay qua lon thi su kien
tran ra ngoai cua so va rule KHONG kich hoat. Giu --delay <= 1.0 khi demo.

Sau khi chay, kiem tra alert tren dashboard (index wazuh-alerts-*) va alert
tuong quan (index siem-correlated-*).
"""

from __future__ import annotations

import argparse
import random
import socket
import sys
import time
from datetime import datetime
from typing import NamedTuple

ERP_HOST = "erp01"
ERP_TAG = "erpapp"
FW_HOST = "fw01"
FW_TAG = "kernel"

# Rule 100121 (password spraying) dung <different_field>dstuser</different_field> nen can
# du 8 tai khoan KHAC NHAU trong cua so 300s. Danh sach phai co it nhat 9 ten khac nhau,
# lap lai ten se lam rule khong kich hoat.
USERS = [
    "nvhung", "ketoan1", "thukho2", "admin", "banhang3",
    "ttmai", "lvminh", "phlong", "dtquyen", "nvtuan",
]

# Dai IP dung cho kich ban mot tai khoan dang nhap tu nhieu noi.
ROAMING_IPS = ["203.0.113.77", "198.51.100.42", "192.0.2.155", "203.0.113.201"]

# Cong hay bi quet trong giai doan do tham.
SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 443,
    445, 1433, 3306, 3389, 5432, 5900, 8080, 8443,
]


class Event(NamedTuple):
    """Mot su kien log kem nguon sinh ra no."""

    host: str
    tag: str
    message: str


def syslog_line(ev: Event) -> str:
    """Bo khung syslog RFC3164 de decoder cha (program_name) bat duoc."""
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    # PRI 13 = facility 1 (user), severity 5 (notice)
    return f"<13>{ts} {ev.host} {ev.tag}: {ev.message}"


# ---------- su kien ung dung ERP ----------


def ev_auth_fail(user: str, srcip: str) -> Event:
    msg = f"AUTH result=FAILED user={user} srcip={srcip} reason=bad_password path=/api/login"
    return Event(ERP_HOST, ERP_TAG, msg)


def ev_auth_ok(user: str, srcip: str) -> Event:
    msg = f"AUTH result=OK user={user} srcip={srcip} reason=none path=/api/login"
    return Event(ERP_HOST, ERP_TAG, msg)


def ev_export(user: str, srcip: str, rows: int, module: str = "customer") -> Event:
    msg = f"EXPORT rows={rows} module={module} user={user} srcip={srcip} file={module}.csv"
    return Event(ERP_HOST, ERP_TAG, msg)


def ev_perm_grant(actor: str, target: str, srcip: str, role: str = "admin") -> Event:
    msg = f"PERM action=grant role={role} target={target} user={actor} srcip={srcip}"
    return Event(ERP_HOST, ERP_TAG, msg)


def ev_price_change(user: str, srcip: str) -> Event:
    order = f"DH{datetime.now():%Y%m%d}{random.randint(100, 999)}"
    msg = f"TXN action=update_price order={order} old=1200000 new=1000 user={user} srcip={srcip}"
    return Event(ERP_HOST, ERP_TAG, msg)


# ---------- su kien firewall ----------


def ev_fw_drop(srcip: str, dstport: int, dstip: str = "192.168.10.5") -> Event:
    """Log iptables bi chan.

    Decoder 'kernel' co san cua Wazuh bat duoc dinh dang nay, cho ra category
    firewall -> rule 4100 -> rule 100200 cua do an.
    """
    uptime = random.uniform(1000, 99999)
    msg = (
        f"[{uptime:.6f}] IPTABLES-DROP: IN=eth0 OUT= "
        f"MAC=00:1a:2b:3c:4d:5e SRC={srcip} DST={dstip} LEN=44 TOS=0x00 PREC=0x00 "
        f"TTL={random.randint(40, 64)} ID={random.randint(1000, 65000)} PROTO=TCP "
        f"SPT={random.randint(30000, 60000)} DPT={dstport} WINDOW=1024 RES=0x00 SYN URGP=0"
    )
    return Event(FW_HOST, FW_TAG, msg)


# ---------- kich ban ----------


def scenario_bruteforce(srcip: str, user: str) -> list[Event]:
    """8 lan sai mat khau lien tiep -> rule 100111 x8, 100120."""
    return [ev_auth_fail(user, srcip) for _ in range(8)]


def scenario_spray(srcip: str) -> list[Event]:
    """Mot IP thu lan luot nhieu tai khoan KHAC NHAU -> rule 100121.

    Khong lap lai ten: rule doi hoi truong dstuser khac nhau giua cac lan.
    """
    return [ev_auth_fail(u, srcip) for u in USERS]


def scenario_exfil(srcip: str, user: str) -> list[Event]:
    """Xuat du lieu hang loat -> rule 100130, 100131."""
    return [ev_export(user, srcip, random.randint(12000, 40000)) for _ in range(6)]


def scenario_portscan(srcip: str) -> list[Event]:
    """Quet cong: >= 15 lan bi firewall chan trong 60s -> rule 100220.

    Can 15 su kien trong 60 giay nen phai chay voi --delay <= 1.0.
    """
    ports = SCAN_PORTS + SCAN_PORTS[:2]
    return [ev_fw_drop(srcip, p) for p in ports]


def scenario_scan_then_login(srcip: str, user: str) -> list[Event]:
    """Do tham roi khai thac -> rule tuong quan scan_then_login_attempt.

    Cung mot srcip xuat hien o ca log firewall lan log dang nhap, dung thu tu.
    """
    events: list[Event] = []
    events += scenario_portscan(srcip)                       # buoc 1: quet cong
    events += [ev_auth_fail(user, srcip) for _ in range(6)]  # buoc 2: thu dang nhap
    events.append(ev_auth_ok(user, srcip))
    return events


def scenario_impossible_travel(user: str) -> list[Event]:
    """Mot tai khoan dang nhap thanh cong tu >= 3 IP khac nhau trong 15 phut.

    -> rule tuong quan impossible_travel (type distinct, min_cardinality 3).
    Khong co rule Wazuh don le nao bat duoc kich ban nay vi tung su kien deu hop le.
    """
    events: list[Event] = []
    for ip in ROAMING_IPS:
        events.append(ev_auth_ok(user, ip))
        events.append(ev_export(user, ip, random.randint(200, 900), module="order"))
    return events


def scenario_insider(user: str = "ketoan1") -> list[Event]:
    """Nhan vien noi bo lay du lieu truoc khi nghi viec.

    Khac cac kich ban tren o cho KHONG co do mat khau: dang nhap hop le tu IP LAN,
    nhung xuat du lieu nhieu lan va sua gia don hang.
    -> rule 100130, 100131, 100150 va rule tuong quan mass_data_export_by_user.
    """
    lan_ip = "192.168.10.24"
    events = [ev_auth_ok(user, lan_ip)]
    for module in ["customer", "employee", "payroll", "customer", "employee", "payroll"]:
        events.append(ev_export(user, lan_ip, random.randint(11000, 60000), module=module))
    events.append(ev_price_change(user, lan_ip))
    events.append(ev_price_change(user, lan_ip))
    return events


def scenario_full(srcip: str, user: str) -> list[Event]:
    """Chuoi tan cong day du - kich hoat rule tuong quan account_takeover_to_exfil."""
    events: list[Event] = []
    events += scenario_bruteforce(srcip, user)          # buoc 1: do mat khau
    events.append(ev_auth_ok(user, srcip))              # buoc 2: vao duoc
    events.append(ev_perm_grant(user, user, srcip))     # buoc 3: tu cap quyen admin
    events += scenario_exfil(srcip, user)               # buoc 4: xuat du lieu
    events.append(ev_price_change(user, srcip))         # buoc 5: sua gia don hang
    return events


def scenario_all(srcip: str, user: str) -> list[Event]:
    """Chay lan luot moi kich ban - dung khi muon do dashboard co du loai alert."""
    events: list[Event] = []
    events += scenario_scan_then_login(srcip, user)
    events += scenario_full(srcip, user)
    events += scenario_spray(srcip)
    events += scenario_impossible_travel(user)
    events += scenario_insider()
    return events


SCENARIOS = {
    "bruteforce": lambda ip, user: scenario_bruteforce(ip, user),
    "spray": lambda ip, user: scenario_spray(ip),
    "exfil": lambda ip, user: scenario_exfil(ip, user),
    "portscan": lambda ip, user: scenario_portscan(ip),
    "scan-then-login": lambda ip, user: scenario_scan_then_login(ip, user),
    "impossible-travel": lambda ip, user: scenario_impossible_travel(user),
    "insider": lambda ip, user: scenario_insider(),
    "full": lambda ip, user: scenario_full(ip, user),
    "all": lambda ip, user: scenario_all(ip, user),
}

# Mo ta ngan in ra luc chay - giup nguoi demo biet cho doi alert nao.
EXPECTED = {
    "bruteforce": "100111 x8, 100120",
    "spray": "100111, 100121",
    "exfil": "100130, 100131 + mass_data_export_by_user",
    "portscan": "100200, 100220",
    "scan-then-login": "100220, 100111, 100110 + scan_then_login_attempt",
    "impossible-travel": "100110 + impossible_travel",
    "insider": "100130, 100131, 100150 + mass_data_export_by_user",
    "full": "100120, 100141, 100131, 100150 + brute_force_then_success, account_takeover_to_exfil",
    "all": "tat ca cac rule tren",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Gia lap log tan cong gui vao Wazuh")
    parser.add_argument("--host", default="127.0.0.1", help="IP cua Wazuh manager")
    parser.add_argument("--port", type=int, default=514, help="cong syslog UDP")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="full")
    parser.add_argument("--srcip", default="203.0.113.77", help="IP ke tan cong")
    parser.add_argument("--user", default="nvhung", help="tai khoan bi nham")
    parser.add_argument(
        "--delay", type=float, default=1.0, help="giay giua cac su kien (giu <= 1.0)"
    )
    parser.add_argument("--print-only", action="store_true", help="chi in, khong gui")
    args = parser.parse_args()

    events = SCENARIOS[args.scenario](args.srcip, args.user)
    print(f"Kich ban '{args.scenario}': {len(events)} su kien")
    print(f"Alert cho doi: {EXPECTED[args.scenario]}\n")

    sock = None if args.print_only else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for i, ev in enumerate(events, 1):
        line = syslog_line(ev)
        print(f"[{i}/{len(events)}] {line}")
        if sock:
            sock.sendto(line.encode(), (args.host, args.port))
        # Khong ngu khi chi in: --print-only dung de xem truoc, khong mo phong thoi gian.
        if sock and i < len(events):
            time.sleep(args.delay)

    if sock:
        sock.close()
        print(f"\nDa gui {len(events)} su kien toi {args.host}:{args.port}")
        print("Alert tuong quan xuat hien sau toi da mot chu ky quet (POLL_INTERVAL, mac dinh 60s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

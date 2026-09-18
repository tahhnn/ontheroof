#!/usr/bin/env python3
"""Sinh log nen (baseline) cua ung dung ERP noi bo tren erp01.

MUC DICH
    Tao dong log "binh thuong" lien tuc de:
      - agent Wazuh luon co du lieu doc (kiem chung logcollector + decoder con song),
      - dashboard co nen nhieu that, alert tan cong noi bat tren nen do,
      - rule tan suat / rule tuong quan duoc thu nghiem trong dieu kien co nhieu.

    Tan cong KHONG sinh o day. Tan cong do scripts/simulate_attack.py ban syslog
    UDP thang vao manager, hoac do attacker container thuc hien that.

DINH DANG
    Moi dong khop decoder trong custom/decoders/local_decoder.xml:
        <ts> <host> erpapp: AUTH   result= user= srcip= reason= path=
        <ts> <host> erpapp: EXPORT rows= module= user= srcip= file=
        <ts> <host> erpapp: PERM   action= role= target= user= srcip=
        <ts> <host> erpapp: TXN    action= order= old= new= user= srcip=
    Rang buoc cua regex decoder (vi pham la fail-silent, khong bao loi gi):
      - module / action / role la (\\w+)  -> khong duoc chua dau gach ngang,
      - reason / path / file / user / srcip la (\\S+) -> khong duoc chua khoang trang,
      - TXN BAT BUOC co ca old= va new= dang so, ke ca khi action khong lien quan gia.

NGUYEN TAC: LOG NEN KHONG DUOC SINH BAO DONG SAI
    Moi lua chon so lieu duoi day deu bi rang buoc boi rule that trong
    custom/rules/local_rules.xml va correlation/rules/smb_attack_chain.yml.
    Xem khoi HANG RAO ben duoi, va chay --audit de kiem chung lai.

CHAY
    python3 app-logger.py                 # ghi ra stdout, entrypoint chuyen vao app.log
    python3 app-logger.py --audit 14      # mo phong 14 ngay bang dong ho ao, kiem tra hang rao
    python3 app-logger.py --rate 3        # tang nhip x3 khi can nhieu du lieu nhanh
    APP_LOGGER_ALWAYS_BUSINESS=1 python3 app-logger.py   # bo qua nhip ngay/dem
"""

from __future__ import annotations

import argparse
import heapq
import itertools
import math
import os
import random
import socket
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

HOST = socket.gethostname()
TAG = "erpapp"

# --------------------------------------------------------------------------
# HANG RAO - nguong phai nam DUOI dieu kien cua tung rule that
# --------------------------------------------------------------------------
# rule 100131 (level 10): erp.rows khop ^[1-9][0-9]{4,}$ tuc >= 10000 dong.
MAX_ROWS = 9500

# rule 100120 (brute force): 6 lan 100111 cung srcip + cung dstuser / 120s.
# rule 100121 (spraying):    8 lan 100111 cung srcip + dstuser KHAC NHAU / 300s.
# correlation account_takeover_to_exfil: 3 lan 100111 cung dstuser / 3600s roi
#   login OK roi export - tuc go sai mat khau la chang dau cua "chiem tai khoan".
# Vi vay: toi da 2 lan sai mat khau cho moi tai khoan trong 1 gio.
MAX_FAIL_PER_USER = 2
FAIL_WINDOW = 3600

# correlation impossible_travel: 3 srcip KHAC NHAU cho cung dstuser / 900s.
# Moi nhan vien duoc gan CO DINH mot IP may tram; ai lam tu xa duoc gan CO DINH
# mot IP VPN (chon mot lan, khong doi) - toi da 2 IP moi nguoi.
MAX_DISTINCT_IP_PER_USER = 2

# correlation mass_data_export_by_user: 5 lan rule 100130/100131 cung dstuser / 1800s.
# rule 100130 (level 5) khop module customer|employee|payroll.
MAX_SENSITIVE_EXPORT_PER_USER = 2
SENSITIVE_WINDOW = 1800

# rule 100141 (level 12) + correlation privilege_then_config_change:
# cap quyen admin/superadmin la su kien tan cong, log nen TUYET DOI khong sinh.
FORBIDDEN_ROLES = frozenset({"admin", "superadmin", "root"})

SENSITIVE_MODULES = frozenset({"customer", "employee", "payroll"})


# --------------------------------------------------------------------------
# NHAN SU - danh tinh on dinh: mot nguoi, mot may, mot bo quyen
# --------------------------------------------------------------------------
# Dai IP trung mang LAN trong scripts/simulate_attack.py (firewall dstip
# 192.168.10.5, insider 192.168.10.24) de so do mang nhat quan giua hai nguon log.
@dataclass(frozen=True)
class Staff:
    user: str
    title: str
    ip: str                        # may tram co dinh
    remote: bool                   # co lam viec tu xa (duoc cap 1 IP VPN co dinh)
    modules: tuple                 # module duoc xuat thuong xuyen
    sensitive: tuple               # module nhay cam duoc phep xuat (rat thua thot)
    txn_actions: tuple             # (action, trong so)
    grantable: tuple               # role duoc phep cap (khong bao gio la admin)
    sessions_weight: float         # tan so dang nhap tuong doi
    n_actions: tuple               # so thao tac moi phien (min, max)


STAFF = (
    Staff(
        user="nvhung", title="nhan vien ban hang", ip="192.168.10.21", remote=False,
        modules=("order", "product"), sensitive=(),
        txn_actions=(("create_order", 0.45), ("update_order", 0.35), ("confirm_order", 0.20)),
        grantable=(), sessions_weight=1.4, n_actions=(12, 34),
    ),
    Staff(
        user="banhang3", title="nhan vien ban hang", ip="192.168.10.22", remote=True,
        modules=("order", "product"), sensitive=(),
        txn_actions=(("create_order", 0.50), ("update_order", 0.30), ("cancel_order", 0.20)),
        grantable=(), sessions_weight=1.2, n_actions=(10, 28),
    ),
    Staff(
        user="thukho2", title="thu kho", ip="192.168.10.23", remote=False,
        modules=("inventory", "product"), sensitive=(),
        txn_actions=(("adjust_stock", 0.55), ("receive_goods", 0.30), ("issue_goods", 0.15)),
        grantable=(), sessions_weight=1.0, n_actions=(8, 24),
    ),
    Staff(
        user="ketoan1", title="ke toan", ip="192.168.10.24", remote=False,
        modules=("invoice", "report"), sensitive=("customer",),
        txn_actions=(("close_invoice", 0.52), ("post_payment", 0.46), ("update_price", 0.02)),
        grantable=(), sessions_weight=1.1, n_actions=(10, 26),
    ),
    Staff(
        user="ttmai", title="ke toan truong", ip="192.168.10.25", remote=True,
        modules=("report", "invoice"), sensitive=("customer", "payroll"),
        txn_actions=(("approve_invoice", 0.60), ("post_payment", 0.38), ("update_price", 0.02)),
        grantable=("viewer", "accountant", "approver"), sessions_weight=0.7, n_actions=(6, 18),
    ),
    Staff(
        user="lvminh", title="truong phong kinh doanh", ip="192.168.10.26", remote=True,
        modules=("report", "order"), sensitive=("customer",),
        txn_actions=(("approve_order", 0.62), ("update_order", 0.35), ("update_price", 0.03)),
        grantable=("viewer", "sales"), sessions_weight=0.6, n_actions=(5, 15),
    ),
    Staff(
        user="itadmin", title="quan tri he thong", ip="192.168.10.30", remote=True,
        modules=("sysconfig", "report"), sensitive=("employee",),
        txn_actions=(("update_config", 0.60), ("rebuild_index", 0.40)),
        grantable=("viewer", "sales", "accountant", "warehouse"), sessions_weight=0.35,
        n_actions=(3, 10),
    ),
)

# IP VPN co dinh cho tung nguoi lam viec tu xa - gan mot lan, khong doi, de moi
# tai khoan chi bao gio thay toi da 2 srcip (xem MAX_DISTINCT_IP_PER_USER).
VPN_POOL = ("100.64.12.31", "100.64.12.44", "100.64.12.58", "100.64.12.77")
VPN_IP = {s.user: VPN_POOL[i % len(VPN_POOL)]
          for i, s in enumerate(s for s in STAFF if s.remote)}
P_REMOTE_SESSION = 0.18

# Tac vu chay dem cua chinh may chu - khong co nguoi dang nhap nen KHONG sinh
# su kien AUTH (tranh rule 100122 "dang nhap ngoai gio" bao sai moi dem).
BATCH_USER = "svc_batch"
BATCH_IP = "192.168.10.5"
BATCH_HOUR, BATCH_MINUTE = 1, 5

LOGIN_PATHS = ("/api/login", "/api/auth/login", "/login")
FAIL_REASONS = (("bad_password", 0.85), ("expired_password", 0.10), ("mfa_timeout", 0.05))

FILE_STEMS = {
    "order": ("don-hang", "sales-order"),
    "product": ("danh-muc-hang", "product-list"),
    "inventory": ("ton-kho", "stock-card"),
    "invoice": ("hoa-don", "invoice-list"),
    "report": ("bao-cao-doanh-thu", "bao-cao-cong-no", "bao-cao-ban-hang"),
    "customer": ("khach-hang",),
    "payroll": ("bang-luong",),
    "employee": ("nhan-su",),
    "sysconfig": ("cau-hinh-he-thong",),
}


# --------------------------------------------------------------------------
# NHIP LAM VIEC - gio Viet Nam (container dat TZ=Asia/Ho_Chi_Minh)
# --------------------------------------------------------------------------
def activity(dt: datetime) -> float:
    """He so nhip lam viec trong [0, 1]. 0 = khong ai lam viec.

    Tra ve 0 trong khung 21:00-07:00 nen log nen khong bao gio sinh su kien dang
    nhap ban dem. Do la co y: rule 100122 doi chieu dong ho HE THONG (khung
    15:00-22:00 UTC = 22:00-05:00 gio VN), nen mot lan dang nhap nen luc 3h sang
    se thanh canh bao "dang nhap ngoai gio lam viec" hoan toan sai.
    """
    if ALWAYS_BUSINESS:
        return 1.0

    weekday = dt.weekday()                     # 0 = thu hai
    if weekday == 6:                           # chu nhat - gan nhu khong ai vao
        day = 0.04
    elif weekday == 5:                         # thu bay - lam nua ngay
        day = 0.25 if dt.hour < 12 else 0.08
    else:
        day = 1.0

    h = dt.hour + dt.minute / 60.0
    if 7.0 <= h < 8.0:
        hour = 0.35                            # den som, mo may
    elif 8.0 <= h < 11.5:
        hour = 1.00                            # cao diem buoi sang
    elif 11.5 <= h < 12.0:
        hour = 0.55
    elif 12.0 <= h < 13.25:
        hour = 0.12                            # nghi trua
    elif 13.25 <= h < 17.0:
        hour = 0.95                            # cao diem buoi chieu
    elif 17.0 <= h < 18.5:
        hour = 0.40                            # ve dan
    elif 18.5 <= h < 21.0:
        hour = 0.10                            # lam them
    else:
        hour = 0.0                             # 21:00-07:00 khong co nguoi
    return day * hour


PEAK_SESSION_INTERVAL = 165.0   # giay giua hai phien dang nhap luc cao diem


# --------------------------------------------------------------------------
# HA TANG: dong ho (that / ao) va ngan sach hang rao
# --------------------------------------------------------------------------
class Clock:
    """Dong ho dung chung cho che do chay that va che do audit."""

    def __init__(self, start=None, virtual: bool = False) -> None:
        self.virtual = virtual
        self._t = (start or datetime.now()).timestamp()

    def epoch(self) -> float:
        return self._t

    def now(self) -> datetime:
        return datetime.fromtimestamp(self._t)

    def wait_until(self, ts: float) -> None:
        if ts <= self._t:
            return
        if self.virtual:
            self._t = ts
        else:
            time.sleep(ts - self._t)
            self._t = max(ts, time.time())     # chong troi khi sleep bi ngat


class Budget:
    """Dem su kien theo cua so truot de khong vuot nguong cua rule."""

    def __init__(self) -> None:
        self._hits = defaultdict(deque)

    def _window(self, kind: str, key: str, ts: float, window: float) -> deque:
        q = self._hits[(kind, key)]
        while q and q[0] <= ts - window:
            q.popleft()
        return q

    def take(self, kind: str, key: str, ts: float, window: float, limit: int) -> bool:
        q = self._window(kind, key, ts, window)
        if len(q) >= limit:
            return False
        q.append(ts)
        return True


# --------------------------------------------------------------------------
# SINH GIA TRI
# --------------------------------------------------------------------------
def weighted(pairs: tuple) -> str:
    return random.choices([p[0] for p in pairs], weights=[p[1] for p in pairs], k=1)[0]


def export_rows(module: str) -> int:
    """Phan bo lech phai: phan lon la truy van nho, doi khi mot ban ket xuat lon.

    Chan cung duoi MAX_ROWS de khong bao gio khop rule 100131 (level 10). Module
    nhay cam giu o quy mo nho - ke toan xuat mot nhom khach hang, khong ai xuat
    ca co so du lieu trong gio lam viec binh thuong.
    """
    if module in SENSITIVE_MODULES:
        return random.randint(15, 800)
    rows = int(random.lognormvariate(math.log(60), 1.25)) + 1
    return min(rows, MAX_ROWS)


def export_file(module: str, dt: datetime) -> str:
    stem = random.choice(FILE_STEMS.get(module, (module,)))
    stamp = dt.strftime("%Y%m") if random.random() < 0.5 else dt.strftime("%Y%m%d")
    ext = random.choices(("csv", "xlsx", "pdf"), weights=(0.6, 0.3, 0.1), k=1)[0]
    return f"{stem}-{stamp}.{ext}"


_ORDER_SEQ = itertools.count(random.randint(120, 400))


def doc_id(prefix: str, dt: datetime) -> str:
    return f"{prefix}{dt:%Y%m%d}{next(_ORDER_SEQ) % 1000:03d}"


def txn_values(action: str):
    """Cap (old, new) cho truong old= / new= ma decoder erpapp-txn doi hoi.

    Decoder dat ten hai truong nay la erp.old_price / erp.new_price, nhung voi
    action khong lien quan gia thi day la so luong / so tien chung. Chi action
    update_price moi khop rule 100150 (level 7, nhom fraud), nen action do duoc
    giu thua thot trong bang txn_actions cua tung nhan su.
    """
    if action == "update_price":
        old = random.choice((50_000, 120_000, 250_000, 480_000, 1_200_000, 2_400_000))
        new = max(1_000, int(round(old * (1 + random.uniform(-0.25, 0.25)) / 1_000)) * 1_000)
        return old, new
    if action in ("adjust_stock", "receive_goods", "issue_goods"):
        old = random.randint(0, 900)
        return old, max(0, old + random.randint(-60, 180))
    if action in ("close_invoice", "post_payment", "approve_invoice"):
        amount = random.randint(1, 400) * 100_000
        return amount, amount                  # ghi nhan, khong doi so tien
    old = random.randint(1, 60)
    return old, max(1, old + random.randint(-5, 12))


# --------------------------------------------------------------------------
# SINH DONG LOG
# --------------------------------------------------------------------------
def fmt(dt: datetime, message: str) -> str:
    return f"{dt:%b %d %H:%M:%S} {HOST} {TAG}: {message}"


def line_auth(result: str, user: str, ip: str, reason: str) -> str:
    return (f"AUTH result={result} user={user} srcip={ip} "
            f"reason={reason} path={random.choice(LOGIN_PATHS)}")


def line_export(rows: int, module: str, user: str, ip: str, fname: str) -> str:
    return f"EXPORT rows={rows} module={module} user={user} srcip={ip} file={fname}"


def line_perm(action: str, role: str, target: str, actor: str, ip: str) -> str:
    assert role not in FORBIDDEN_ROLES, "log nen khong duoc cap quyen admin"
    return f"PERM action={action} role={role} target={target} user={actor} srcip={ip}"


def line_txn(action: str, order: str, old: int, new: int, user: str, ip: str) -> str:
    return f"TXN action={action} order={order} old={old} new={new} user={user} srcip={ip}"


# --------------------------------------------------------------------------
# MOT PHIEN LAM VIEC
# --------------------------------------------------------------------------
@dataclass
class Sim:
    clock: Clock
    budget: Budget = field(default_factory=Budget)

    def session_ip(self, staff: Staff) -> str:
        if staff.remote and random.random() < P_REMOTE_SESSION:
            return VPN_IP[staff.user]
        return staff.ip

    def build_session(self, staff: Staff, start: float):
        """Mot phien: dang nhap (co the go sai) roi mot chuoi thao tac nghiep vu."""
        out = []
        ip = self.session_ip(staff)
        t = start

        # Go sai mat khau that: 1 lan, doi khi 2, roi vao duoc. Ngan sach
        # MAX_FAIL_PER_USER/gio giu no duoi moc 3 lan cua correlation
        # account_takeover_to_exfil va duoi moc 6 lan cua rule 100120.
        if random.random() < 0.10:
            for _ in range(1 if random.random() < 0.8 else 2):
                if not self.budget.take("fail", staff.user, t, FAIL_WINDOW,
                                        MAX_FAIL_PER_USER):
                    break
                out.append((t, line_auth("FAILED", staff.user, ip, weighted(FAIL_REASONS))))
                t += random.uniform(4.0, 18.0)

        out.append((t, line_auth("OK", staff.user, ip, "none")))

        for _ in range(random.randint(*staff.n_actions)):
            t += random.uniform(12.0, 240.0)
            dt = datetime.fromtimestamp(t)
            roll = random.random()
            if roll < 0.004 and staff.grantable:
                # Cap quyen nghiep vu that: rule 100140 (level 8) se bao - day la
                # alert dung, thuoc dau vet kiem toan. Role admin bi cam tu goc.
                target = random.choice([s.user for s in STAFF if s.user != staff.user])
                out.append((t, line_perm("grant", random.choice(staff.grantable),
                                         target, staff.user, ip)))
            elif roll < 0.18:
                module = self.pick_module(staff, t)
                out.append((t, line_export(export_rows(module), module, staff.user, ip,
                                           export_file(module, dt))))
            else:
                action = weighted(staff.txn_actions)
                old, new = txn_values(action)
                prefix = "HD" if ("invoice" in action or "payment" in action) else "DH"
                out.append((t, line_txn(action, doc_id(prefix, dt), old, new,
                                        staff.user, ip)))
        return out

    def pick_module(self, staff: Staff, ts: float) -> str:
        """Uu tien module thuong ngay; module nhay cam bi ngan sach chan.

        rule 100130 (level 5) bat moi lan xuat customer/employee/payroll, va
        correlation mass_data_export_by_user nổ khi 5 lan / 30 phut cung mot
        nguoi. Giu <= MAX_SENSITIVE_EXPORT_PER_USER de nen chi co vai alert muc
        5 rai rac trong ngay - dung nhu thuc te, nhung khong thanh chuoi.
        """
        if staff.sensitive and random.random() < 0.08:
            module = random.choice(staff.sensitive)
            if self.budget.take("sens", staff.user, ts, SENSITIVE_WINDOW,
                                MAX_SENSITIVE_EXPORT_PER_USER):
                return module
        return random.choice(staff.modules)

    def build_batch(self, day: datetime):
        """Tac vu dem cua may chu: chot so, ket xuat bao cao, don chi muc.

        KHONG co AUTH: tac vu chay bang service account tren chinh may chu,
        khong qua man hinh dang nhap. Nho vay ban dem khong sinh rule 100122.
        Module 'report' khong nam trong SENSITIVE_MODULES nen cung khong sinh
        rule 100130 - dem la khoang lang cua dashboard, dung nhu thuc te.
        """
        out = []
        t = day.replace(hour=BATCH_HOUR, minute=BATCH_MINUTE, second=0,
                        microsecond=0).timestamp() + random.uniform(0, 600)
        for action in ("close_invoice", "rebuild_index", "post_payment"):
            old, new = txn_values(action)
            out.append((t, line_txn(action, doc_id("HD", datetime.fromtimestamp(t)),
                                    old, new, BATCH_USER, BATCH_IP)))
            t += random.uniform(20.0, 120.0)
        for module in ("report", "inventory", "report"):
            out.append((t, line_export(export_rows(module), module, BATCH_USER, BATCH_IP,
                                       export_file(module, datetime.fromtimestamp(t)))))
            t += random.uniform(30.0, 180.0)
        return out

    def next_arrival(self, after: float) -> float:
        """Thoi diem phien dang nhap ke tiep, theo tien trinh Poisson khong deu.

        Nhay qua cac khoang khong ai lam viec (dem, chu nhat) thay vi don phien
        vao dau gio - neu don, 8h sang moi ngay se co mot cum dang nhap dot ngot,
        de bi rule tan suat coi la bat thuong.
        """
        t = after
        for _ in range(20_000):
            rate = activity(datetime.fromtimestamp(t)) * RATE
            if rate <= 0.0:
                t += 300.0
                continue
            cand = t + random.expovariate(rate / PEAK_SESSION_INTERVAL)
            if ALWAYS_BUSINESS or activity(datetime.fromtimestamp(cand)) > 0.0:
                return cand
            t = cand
        return t + 3600.0

    def pick_staff(self) -> Staff:
        return random.choices(STAFF, weights=[s.sessions_weight for s in STAFF], k=1)[0]


# --------------------------------------------------------------------------
# VONG CHAY
# --------------------------------------------------------------------------
def run(sim: Sim, emit, until=None) -> None:
    clock = sim.clock
    pending = []
    seq = itertools.count()

    def push(events) -> None:
        for ts, msg in events:
            heapq.heappush(pending, (ts, next(seq), msg))

    next_session = sim.next_arrival(clock.epoch())
    next_batch = clock.now().replace(hour=BATCH_HOUR, minute=BATCH_MINUTE,
                                     second=0, microsecond=0)
    if next_batch.timestamp() <= clock.epoch():
        next_batch += timedelta(days=1)

    while until is None or clock.epoch() < until:
        head = pending[0][0] if pending else math.inf
        batch_at = next_batch.timestamp()
        soonest = min(head, next_session, batch_at)
        if until is not None and soonest >= until:
            return

        if soonest == batch_at:
            clock.wait_until(batch_at)
            push(sim.build_batch(next_batch))
            next_batch += timedelta(days=1)
        elif soonest == next_session:
            clock.wait_until(next_session)
            push(sim.build_session(sim.pick_staff(), next_session))
            next_session = sim.next_arrival(clock.epoch())
        else:
            ts, _, msg = heapq.heappop(pending)
            clock.wait_until(ts)
            emit(datetime.fromtimestamp(ts), msg)


# --------------------------------------------------------------------------
# AUDIT - kiem chung log nen khong vuot nguong rule nao
# --------------------------------------------------------------------------
def _peak(series, window: float) -> int:
    """So su kien nhieu nhat cua mot key trong bat ky cua so `window` giay nao."""
    best = 0
    for stamps in series.values():
        stamps.sort()
        lo = 0
        for hi, t in enumerate(stamps):
            while stamps[lo] <= t - window:
                lo += 1
            best = max(best, hi - lo + 1)
    return best


def audit(days: int, show: bool) -> int:
    start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    sim = Sim(Clock(start=start, virtual=True))
    rows = []

    def collect(dt: datetime, msg: str) -> None:
        rows.append((dt, msg))
        if show:
            print(fmt(dt, msg))

    run(sim, collect, until=(start + timedelta(days=days)).timestamp())

    verbs = defaultdict(int)
    fails = defaultdict(list)
    logins = defaultdict(list)
    sens = defaultdict(list)
    max_rows = 0
    bad_roles = 0
    night_auth = 0
    price_changes = 0

    for dt, msg in rows:
        ts = dt.timestamp()
        verb = msg.split(" ", 1)[0]
        verbs[verb] += 1
        kv = dict(p.split("=", 1) for p in msg.split(" ")[1:] if "=" in p)
        if verb == "AUTH":
            if not (5 <= dt.hour < 22):
                night_auth += 1
            if kv["result"] == "FAILED":
                fails[kv["user"]].append(ts)
            else:
                logins[kv["user"]].append((ts, kv["srcip"]))
        elif verb == "EXPORT":
            max_rows = max(max_rows, int(kv["rows"]))
            if kv["module"] in SENSITIVE_MODULES:
                sens[kv["user"]].append(ts)
        elif verb == "PERM":
            if kv["role"] in FORBIDDEN_ROLES:
                bad_roles += 1
        elif verb == "TXN" and kv["action"] == "update_price":
            price_changes += 1

    max_distinct_ip = 0
    for stamps in logins.values():
        stamps.sort()
        lo = 0
        for hi, (t, _) in enumerate(stamps):
            while stamps[lo][0] <= t - 900:
                lo += 1
            max_distinct_ip = max(max_distinct_ip,
                                  len({ip for _, ip in stamps[lo:hi + 1]}))

    total = len(rows)
    print(f"# audit {days} ngay - {total} dong ({total / max(days, 1):.0f} dong/ngay)")
    for verb in ("AUTH", "EXPORT", "PERM", "TXN"):
        print(f"  {verb:7s} {verbs[verb]:6d}")
    print(f"  trong do update_price: {price_changes} (rule 100150 level 7)")

    checks = (
        ("rule 100131 xuat du lieu hang loat",
         f"rows toi da {max_rows}", max_rows < 10_000),
        ("rule 100120 brute force",
         f"toi da {_peak(fails, 120)} lan sai/120s/user", _peak(fails, 120) < 6),
        ("correlation account_takeover_to_exfil",
         f"toi da {_peak(fails, 3600)} lan sai/3600s/user", _peak(fails, 3600) < 3),
        ("correlation impossible_travel",
         f"toi da {max_distinct_ip} srcip/900s/user", max_distinct_ip < 3),
        ("correlation mass_data_export_by_user",
         f"toi da {_peak(sens, 1800)} lan xuat nhay cam/1800s/user",
         _peak(sens, 1800) < 5),
        ("rule 100141 cap quyen admin", f"{bad_roles} dong", bad_roles == 0),
        ("rule 100122 dang nhap ngoai gio",
         f"{night_auth} dong AUTH trong 22:00-05:00", night_auth == 0),
    )
    failed = sum(0 if ok else 1 for _, _, ok in checks)
    for name, detail, ok in checks:
        print(f"  [{'OK  ' if ok else 'FAIL'}] {name}: {detail}")
    print("# ket luan:", "log nen khong kich hoat rule tan cong nao" if not failed
          else f"{failed} hang rao bi vuot")
    return 1 if failed else 0


# --------------------------------------------------------------------------
def main() -> int:
    global RATE, ALWAYS_BUSINESS

    parser = argparse.ArgumentParser(
        description="Sinh log nen cua ung dung ERP tren erp01.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rate", type=float,
                        default=float(os.environ.get("APP_LOGGER_RATE", "1")),
                        help="he so nhan nhip su kien (mac dinh 1)")
    parser.add_argument("--seed", type=int,
                        default=int(os.environ["APP_LOGGER_SEED"])
                        if os.environ.get("APP_LOGGER_SEED") else None,
                        help="hat giong random de tai lap duoc")
    parser.add_argument("--always-business", action="store_true",
                        default=os.environ.get("APP_LOGGER_ALWAYS_BUSINESS") == "1",
                        help="bo qua nhip ngay/dem. CANH BAO: chay ngoai khung 05:00-22:00 "
                             "gio VN se sinh rule 100122 'dang nhap ngoai gio' vo nghia")
    parser.add_argument("--audit", type=int, metavar="NGAY",
                        help="mo phong bang dong ho ao roi kiem tra hang rao, khong ghi log")
    parser.add_argument("--print", dest="show", action="store_true",
                        help="in ca log khi audit")
    args = parser.parse_args()

    RATE = max(args.rate, 0.01)
    ALWAYS_BUSINESS = args.always_business
    if args.seed is not None:
        random.seed(args.seed)

    if args.audit:
        return audit(args.audit, args.show)

    def emit(dt: datetime, msg: str) -> None:
        print(fmt(dt, msg))
        sys.stdout.flush()

    run(Sim(Clock()), emit)
    return 0


RATE = 1.0
ALWAYS_BUSINESS = False

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)

#!/usr/bin/env bash
# Tinh huong F: kiem thu AM TINH tu dong cho decoder/rule.
#
# Khac gi scripts/test_rules.sh?
#   test_rules.sh in ket qua ra man hinh, ky vong ghi trong comment, doi chieu
#   BANG MAT. Cach do bat duoc loi "rule khong no" nhung KHONG bat duoc loi
#   "rule no nham" - dung loai loi ^OK$ da vap (README muc 5, luu y 4).
#
#   Script nay khai bao ky vong thanh DU LIEU va tu dong so sanh:
#     MUST     = dong log nay PHAI ra rule id nay
#     MUST_NOT = dong log nay TUYET DOI KHONG duoc ra rule id nay
#
#   Thoat voi ma 1 neu co bat ky ca nao that bai -> cam vao CI duoc.
#
#   bash scripts/negative_rule_test.sh
#
# Nguyen tac rut ra tu loi ^OK$: moi phep so khop tren truong trang thai deu
# phai neo ^...$. Khong neo la so khop chuoi con.

set -uo pipefail

CONTAINER="${CONTAINER:-siem-raw-wazuh.manager-1}"

PASS=0
FAIL=0

# Chay mot dong log qua wazuh-logtest, tra ve rule id bat duoc (rong neu khong co).
run_logtest() {
  local line="$1"
  printf '%s\n' "$line" \
    | MSYS_NO_PATHCONV=1 docker exec -i "$CONTAINER" /var/ossec/bin/wazuh-logtest 2>&1 \
    | grep -oE "id: '[0-9]+'" | head -1 | grep -oE '[0-9]+' || true
}

# assert MUST <rule_id> <mo ta> <dong log>
must() {
  local want="$1" desc="$2" line="$3"
  local got
  got=$(run_logtest "$line")
  if [[ "$got" == "$want" ]]; then
    printf '  \033[32mPASS\033[0m  %-52s -> %s\n' "$desc" "$got"
    PASS=$((PASS + 1))
  else
    printf '  \033[31mFAIL\033[0m  %-52s -> mong doi %s, nhan duoc %s\n' \
      "$desc" "$want" "${got:-<khong co rule>}"
    printf '        log: %s\n' "$line"
    FAIL=$((FAIL + 1))
  fi
}

# assert MUST_NOT <rule_id> <mo ta> <dong log>
must_not() {
  local forbidden="$1" desc="$2" line="$3"
  local got
  got=$(run_logtest "$line")
  if [[ "$got" == "$forbidden" ]]; then
    printf '  \033[31mFAIL\033[0m  %-52s -> KHONG duoc ra %s nhung da ra\n' "$desc" "$forbidden"
    printf '        log: %s\n' "$line"
    FAIL=$((FAIL + 1))
  else
    printf '  \033[32mPASS\033[0m  %-52s -> %s (khac %s, dung)\n' \
      "$desc" "${got:-<khong co rule>}" "$forbidden"
    PASS=$((PASS + 1))
  fi
}

section() { printf '\n\033[1m===== %s =====\033[0m\n' "$1"; }

# ---------------------------------------------------------------------------
section "NHOM 1 - Trang thai dang nhap phai neo ^OK\$ / ^FAILED\$"
# Day la loi da vap. Khong neo thi NOTOK/TOKEN_EXPIRED/BLOCKED deu lot vao rule
# "dang nhap thanh cong", khien brute_force_then_success ket luan NGUOC: tan cong
# bi khoa tai khoan lai bi bao la da chiem duoc tai khoan.

must     100110 "AUTH result=OK -> dang nhap thanh cong" \
  'Aug 25 13:40:12 erp01 erpapp: AUTH result=OK user=nvhung srcip=192.168.10.24 reason=none path=/api/login'

must_not 100110 "AUTH result=NOTOK KHONG duoc la thanh cong" \
  'Aug 25 13:40:12 erp01 erpapp: AUTH result=NOTOK user=nvhung srcip=192.168.10.24 reason=none path=/api/login'

must_not 100110 "AUTH result=TOKEN_EXPIRED KHONG duoc la thanh cong" \
  'Aug 25 13:40:12 erp01 erpapp: AUTH result=TOKEN_EXPIRED user=nvhung srcip=192.168.10.24 reason=expired path=/api/login'

must_not 100110 "AUTH result=BLOCKED KHONG duoc la thanh cong" \
  'Aug 25 13:40:12 erp01 erpapp: AUTH result=BLOCKED user=nvhung srcip=192.168.10.24 reason=locked path=/api/login'

must     100111 "AUTH result=FAILED -> dang nhap that bai" \
  'Aug 25 13:40:12 erp01 erpapp: AUTH result=FAILED user=nvhung srcip=192.168.10.24 reason=bad_password path=/api/login'

must_not 100111 "AUTH result=FAILED_OK KHONG duoc la that bai" \
  'Aug 25 13:40:12 erp01 erpapp: AUTH result=FAILED_OK user=nvhung srcip=192.168.10.24 reason=none path=/api/login'

must_not 100111 "AUTH result=NOT_FAILED KHONG duoc la that bai" \
  'Aug 25 13:40:12 erp01 erpapp: AUTH result=NOT_FAILED user=nvhung srcip=192.168.10.24 reason=none path=/api/login'

# ---------------------------------------------------------------------------
section "NHOM 2 - Nguong 10000 dong phai so BANG SO, khong dem chu so"
# os_regex khong hieu lop ky tu [1-9]; regex cu ^\d\d\d\d\d+$ chi DEM SO CHU SO
# nen rows=00012 (12 dong) bi bao la "xuat hang loat" muc 10.

must     100131 "rows=10000 -> xuat hang loat (dung nguong)" \
  'Aug 25 13:40:12 erp01 erpapp: EXPORT rows=10000 module=customer user=u srcip=1.1.1.1 file=a.csv'

must     100131 "rows=25000 -> xuat hang loat" \
  'Aug 25 13:40:12 erp01 erpapp: EXPORT rows=25000 module=customer user=u srcip=1.1.1.1 file=a.csv'

must_not 100131 "rows=9999 KHONG duoc la xuat hang loat" \
  'Aug 25 13:40:12 erp01 erpapp: EXPORT rows=9999 module=customer user=u srcip=1.1.1.1 file=a.csv'

must_not 100131 "rows=00012 KHONG duoc la xuat hang loat (5 chu so, 12 dong)" \
  'Aug 25 13:40:12 erp01 erpapp: EXPORT rows=00012 module=customer user=u srcip=1.1.1.1 file=a.csv'

must_not 100131 "rows=00001 KHONG duoc la xuat hang loat" \
  'Aug 25 13:40:12 erp01 erpapp: EXPORT rows=00001 module=customer user=u srcip=1.1.1.1 file=a.csv'

# ---------------------------------------------------------------------------
section "NHOM 3 - Dong log hong phai roi vao 100101, khong duoc bien mat"
# Rule 100101 la chuong bao decoder mu. Neu no khong no thi format log doi ma
# he thong im lang - nguy hiem hon la bao loi.

must 100101 "thieu truong file= -> bao decoder mu" \
  'Aug 25 13:40:12 erp01 erpapp: EXPORT rows=25000 module=customer user=u srcip=1.1.1.1'

must 100101 "sai thu tu truong -> bao decoder mu" \
  'Aug 25 13:40:12 erp01 erpapp: AUTH user=nvhung result=OK srcip=1.1.1.1 reason=none path=/l'

must 100101 "gia tri co khoang trang -> bao decoder mu" \
  'Aug 25 13:40:12 erp01 erpapp: AUTH result=FAILED user=nv hung srcip=1.1.1.1 reason=bad password path=/l'

# ---------------------------------------------------------------------------
section "NHOM 4 - Cap quyen: admin phai tach khoi quyen thuong"
# 100141 (admin, level 12) va 100140 (quyen khac, level 8) phai phan biet duoc.
# Neu khong tach, stage cap_quyen_admin cua privilege_then_config_change se no
# voi moi lan cap quyen bat ky.

must     100141 "PERM role=admin -> cap quyen ADMIN" \
  'Aug 25 13:42:03 erp01 erpapp: PERM action=grant role=admin target=ketoan1 user=nvhung srcip=192.168.10.24'

must_not 100141 "PERM role=viewer KHONG duoc la cap quyen admin" \
  'Aug 25 13:42:03 erp01 erpapp: PERM action=grant role=viewer target=ketoan1 user=nvhung srcip=192.168.10.24'

must_not 100141 "PERM role=administrator_readonly KHONG duoc la admin" \
  'Aug 25 13:42:03 erp01 erpapp: PERM action=grant role=administrator_readonly target=k1 user=nv srcip=192.168.10.24'

# ---------------------------------------------------------------------------
section "KET QUA"
TOTAL=$((PASS + FAIL))
printf '  %d/%d ca dat.\n' "$PASS" "$TOTAL"

if [[ "$FAIL" -gt 0 ]]; then
  printf '  \033[31m%d ca THAT BAI.\033[0m\n\n' "$FAIL"
  echo "  Ca that bai o nhom 1 hoac 4 la loai nguy hiem nhat: rule van no,"
  echo "  nhung no NHAM - he thong bao ket luan nguoc voi su that."
  echo "  Sua decoder/rule roi nap lai:"
  echo "    docker compose -f docker/single-node/docker-compose.yml restart wazuh.manager"
  exit 1
fi

printf '  \033[32mTat ca ca kiem thu am tinh deu dat.\033[0m\n\n'
echo "  Luu y trung thuc de noi voi hoi dong: bo ca nay phu 4 nhom loi DA BIET."
echo "  No khong chung minh khong con loi cung loai - chi chung minh 4 loi da vap"
echo "  se khong quay lai. Moi khi phat hien loi moi, them mot ca vao day."

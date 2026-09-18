#!/usr/bin/env bash
# Tinh huong E + G: do NANG LUC THAT cua he thong dang chay, de tra loi cau hoi
# "chi phi bao nhieu" va "vo o dau khi mo rong" bang SO DO chu khong phai so doan.
#
#   bash scripts/measure_capacity.sh                 # do nhanh
#   bash scripts/measure_capacity.sh --endpoints 50  # ngoai suy cho 50 endpoint
#   bash scripts/measure_capacity.sh --retention 90  # tinh o dia cho 90 ngay
#
# Nguyen tac: chi bao cao so DO DUOC. Cho nao phai ngoai suy thi ghi ro la ngoai suy.

set -uo pipefail

INDEXER_URL="${INDEXER_URL:-https://localhost:9200}"
INDEXER_USER="${INDEXER_USERNAME:-admin}"
INDEXER_PASS="${INDEXER_PASSWORD:-SecretPassword}"
COMPOSE="docker compose -f docker/single-node/docker-compose.yml"

TARGET_ENDPOINTS=0
RETENTION_DAYS=90
SAMPLE_SECONDS=60

while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoints) TARGET_ENDPOINTS="$2"; shift 2 ;;
    --retention) RETENTION_DAYS="$2"; shift 2 ;;
    --sample)    SAMPLE_SECONDS="$2"; shift 2 ;;
    *) echo "Tham so khong hieu: $1"; exit 1 ;;
  esac
done

curl_indexer() { curl -sk -u "${INDEXER_USER}:${INDEXER_PASS}" "$@"; }
step() { printf '\n\033[1m===== %s =====\033[0m\n' "$1"; }

# ---------------------------------------------------------------------------
step "1. Do EPS thuc (dem alert moi trong ${SAMPLE_SECONDS}s)"

count_alerts() {
  curl_indexer "${INDEXER_URL}/wazuh-alerts-*/_count?ignore_unavailable=true&allow_no_indices=true" \
    2>/dev/null | grep -o '"count":[0-9]*' | cut -d: -f2
}

BEFORE=$(count_alerts)
BEFORE="${BEFORE:-0}"
echo "  Alert hien tai: $BEFORE"
echo "  Dang do trong ${SAMPLE_SECONDS} giay..."
sleep "$SAMPLE_SECONDS"
AFTER=$(count_alerts)
AFTER="${AFTER:-0}"

DELTA=$((AFTER - BEFORE))
EPS=$(python -c "print(f'{$DELTA / $SAMPLE_SECONDS:.2f}')")

echo "  Alert moi: $DELTA"
printf '  \033[1mAlert/giay (APS) do duoc: %s\033[0m\n' "$EPS"
echo
echo "  LUU Y: day la ALERT/giay, khong phai EVENT/giay."
echo "  Wazuh chi ghi su kien dat log_alert_level (dang la 3) thanh alert."
echo "  EPS tho o dau vao cao hon nhieu; con so nay moi la con so quyet dinh dung luong."

# ---------------------------------------------------------------------------
step "2. Dung luong dang chiem, theo index"

curl_indexer "${INDEXER_URL}/_cat/indices/wazuh-alerts-*,siem-correlated-*?v&h=index,docs.count,store.size&s=index" 2>/dev/null \
  | sed 's/^/  /'

TOTAL_BYTES=$(curl_indexer "${INDEXER_URL}/_cat/indices/wazuh-alerts-*?h=store.size&bytes=b" 2>/dev/null \
              | awk '{s+=$1} END {print s+0}')
TOTAL_DOCS=$(curl_indexer "${INDEXER_URL}/_cat/indices/wazuh-alerts-*?h=docs.count" 2>/dev/null \
             | awk '{s+=$1} END {print s+0}')

if [[ "${TOTAL_DOCS:-0}" -gt 0 ]]; then
  BYTES_PER_DOC=$(python -c "print(f'{$TOTAL_BYTES / $TOTAL_DOCS:.0f}')")
  echo
  printf '  \033[1mTrung binh %s byte/alert (do duoc, da nen)\033[0m\n' "$BYTES_PER_DOC"
else
  BYTES_PER_DOC=0
  echo
  echo "  Chua co alert nao - chay simulate_attack.py hoac benign_traffic.py truoc."
fi

# ---------------------------------------------------------------------------
step "3. So agent dang ket noi"

AGENTS=$(curl_indexer -X POST "${INDEXER_URL}/wazuh-alerts-*/_search?ignore_unavailable=true" \
  -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"range":{"@timestamp":{"gte":"now-24h"}}},
       "aggs":{"n":{"cardinality":{"field":"agent.name"}}}}' 2>/dev/null \
  | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
AGENTS="${AGENTS:-0}"

echo "  Nguon log co gui alert trong 24h qua: $AGENTS"
if [[ "$AGENTS" -le 1 ]]; then
  echo "  (Moi truong lab - so nay khong dai dien cho doanh nghiep that.)"
fi

# ---------------------------------------------------------------------------
step "4. Suc khoe JVM cua Indexer (nut that so 1 khi mo rong)"

curl_indexer "${INDEXER_URL}/_nodes/stats/jvm?filter_path=nodes.*.jvm.mem.heap_used_percent,nodes.*.jvm.mem.heap_max_in_bytes" 2>/dev/null \
  | python -c "
import sys, json
try:
    nodes = json.load(sys.stdin)['nodes']
except Exception:
    print('  (khong doc duoc)'); sys.exit(0)
for _, n in nodes.items():
    mem = n['jvm']['mem']
    used = mem['heap_used_percent']
    heap_gb = mem['heap_max_in_bytes'] / 1024**3
    flag = ''
    if used > 85:
        flag = '  <-- NGUY HIEM: sap OutOfMemoryError'
    elif used > 70:
        flag = '  <-- can theo doi'
    print(f'  Heap toi da: {heap_gb:.1f} GB   Dang dung: {used}%{flag}')
" 2>/dev/null

echo
echo "  docker-compose.yml dang dat: OPENSEARCH_JAVA_OPTS: \"-Xms1g -Xmx1g\""
echo "  Day la cau hinh LAB. Khi mo rong, day la thu vo dau tien (tinh huong G, nut 1)."

# ---------------------------------------------------------------------------
step "5. Thoi gian mot vong quet cua correlator (nut that so 2)"

$COMPOSE logs --tail=200 correlator 2>/dev/null | grep "Vong quet xong" | tail -5 | sed 's/^/  /'
echo
echo "  Doc con so giay o cuoi moi dong. Neu tien gan POLL_INTERVAL (60s) thi"
echo "  correlator chay noi duoi lien tuc va bat dau canh tranh CPU voi Indexer."

# ---------------------------------------------------------------------------
step "6. Ngoai suy"

if [[ "$TARGET_ENDPOINTS" -gt 0 && "${TOTAL_DOCS:-0}" -gt 0 && "$AGENTS" -gt 0 ]]; then
  python - "$EPS" "$BYTES_PER_DOC" "$AGENTS" "$TARGET_ENDPOINTS" "$RETENTION_DAYS" <<'PYEOF'
import sys

aps, bytes_per_doc, agents, target, retention = (
    float(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3]),
    int(sys.argv[4]), int(sys.argv[5]),
)

aps_per_agent = aps / agents
gb_per_day = aps * 86400 * bytes_per_doc / 1024**3

proj_aps = aps_per_agent * target
proj_gb_day = proj_aps * 86400 * bytes_per_doc / 1024**3
proj_total = proj_gb_day * retention

print(f"  DO DUOC tren he thong hien tai ({agents} nguon log):")
print(f"    {aps:.2f} alert/giay   |   {gb_per_day:.3f} GB/ngay")
print()
print(f"  NGOAI SUY TUYEN TINH cho {target} endpoint:")
print(f"    {proj_aps:.2f} alert/giay")
print(f"    {proj_gb_day:.2f} GB/ngay")
print(f"    {proj_total:.1f} GB cho {retention} ngay luu tru")
print(f"    Nen chuan bi {proj_total * 1.4:.0f} GB o dia (du 40% cho merge va du phong)")
print()
print("  " + "!" * 66)
print("  DAY LA NGOAI SUY TUYEN TINH, KHONG PHAI SO DO.")
print("  Ba ly do khien no co the sai dang ke:")
print("    1. Moi truong lab khong co FIM realtime tren endpoint that.")
print("       ossec.conf bat FIM realtime tren /etc, /usr/bin, /usr/sbin, /bin,")
print("       /sbin, /boot - tren may that se sinh nhieu log hon han.")
print("    2. SCA (12h/lan), syscollector (1h/lan), vulnerability-detection deu")
print("       sinh log theo dot, khong deu - do trong 60 giay khong bat duoc.")
print("    3. Luu luong tan cong that co dot bien, khong tuyen tinh.")
print()
print("  Cach do dung: chay 7 ngay tren moi truong that voi so endpoint that,")
print("  roi lay so do. Truoc hoi dong nen trinh bay PHUONG PHAP nay,")
print("  khong nen trinh bay con so ngoai suy nhu la ket qua.")
print("  " + "!" * 66)
PYEOF
else
  echo "  Chua du du lieu de ngoai suy."
  echo "  Can: (a) co alert trong index, (b) truyen --endpoints N"
  echo
  echo "  Vi du:"
  echo "    python scripts/benign_traffic.py --profile office --duration 600 &"
  echo "    bash scripts/measure_capacity.sh --endpoints 50 --retention 90"
fi

step "TRA LOI GIAM DOC (tinh huong E)"
cat <<'EOF'
  Ba con so nen dua ra, va chi ba con so nay:
    1. GB/ngay do duoc  -> quy ra o dia can mua
    2. Alert/ngay do duoc -> quy ra thoi gian nguoi phai bo ra moi tuan
    3. RAM toi thieu 6 GB (da kiem chung) -> quy ra may chu hoac VPS

  Dieu KHONG nen giau: chi phi con nguoi. SIEM khong phai san pham cam-la-chay.
  Neu khong co ai xem canh bao thi he thong chi ghi log, khong bao ve duoc ai.
EOF

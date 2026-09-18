#!/usr/bin/env bash
# Tinh huong D: dang demo truoc hoi dong, alert Wazuh hien len nhung dashboard
# tuong quan TRONG. Script nay chay lan luot 5 buoc chan doan, tu re den dat.
#
#   bash scripts/troubleshoot_demo.sh
#
# Moi buoc in ra KET LUAN va VIEC CAN LAM, de nguoi demo doc thang tren man hinh
# ma khong phai suy dien.

set -uo pipefail

COMPOSE="docker compose -f docker/single-node/docker-compose.yml"
INDEXER_URL="${INDEXER_URL:-https://localhost:9200}"
INDEXER_USER="${INDEXER_USERNAME:-admin}"
INDEXER_PASS="${INDEXER_PASSWORD:-SecretPassword}"

# So rule tuong quan mong doi - dem tu correlation/rules/smb_attack_chain.yml
EXPECTED_RULES=7

ok()   { printf '  \033[32m[OK]\033[0m   %s\n' "$1"; }
bad()  { printf '  \033[31m[LOI]\033[0m  %s\n' "$1"; }
warn() { printf '  \033[33m[!]\033[0m    %s\n' "$1"; }
step() { printf '\n\033[1m===== %s =====\033[0m\n' "$1"; }

curl_indexer() {
  curl -sk -u "${INDEXER_USER}:${INDEXER_PASS}" "$@"
}

# ---------------------------------------------------------------------------
step "BUOC 0: Cac container co dang chay khong?"

if ! $COMPOSE ps --format '{{.Service}} {{.State}}' 2>/dev/null | grep -q running; then
  bad "Khong co container nao dang chay."
  echo "     Chay: bash scripts/deploy.sh"
  exit 1
fi
$COMPOSE ps --format '  {{.Service}}\t{{.State}}' 2>/dev/null

if ! $COMPOSE ps --format '{{.Service}} {{.State}}' 2>/dev/null | grep -q '^correlator running'; then
  bad "Service 'correlator' KHONG chay. Day la nguyen nhan."
  echo "     Chay: $COMPOSE up -d correlator"
  echo "     Xem vi sao chet: $COMPOSE logs --tail=50 correlator"
  exit 1
fi
ok "correlator dang chay"

# ---------------------------------------------------------------------------
step "BUOC 1: Da qua mot chu ky quet chua? (nguyen nhan hay gap nhat)"

CYCLES=$($COMPOSE logs --tail=200 correlator 2>/dev/null | grep -c "Vong quet xong" || true)
if [[ "$CYCLES" -eq 0 ]]; then
  warn "Chua thay dong 'Vong quet xong' nao trong 200 dong log gan nhat."
  echo "     POLL_INTERVAL mac dinh la 60s. Doi them roi chay lai script nay."
  echo "     Day KHONG phai loi - la hanh vi binh thuong cua kien truc theo chu ky."
else
  ok "Da chay $CYCLES vong quet. Ba vong gan nhat:"
  $COMPOSE logs --tail=200 correlator 2>/dev/null | grep "Vong quet xong" | tail -3 | sed 's/^/       /'

  LAST=$($COMPOSE logs --tail=200 correlator 2>/dev/null | grep "Vong quet xong" | tail -1)
  if echo "$LAST" | grep -q ": 0 alert"; then
    warn "Vong quet gan nhat sinh 0 alert -> co du lieu vao nhung khong khop rule nao."
    echo "     Sang buoc 5 (kiem tra --delay) va buoc 3 (kiem tra rule da nap)."
  fi
fi

# ---------------------------------------------------------------------------
step "BUOC 2: Correlator co ket noi duoc Indexer khong?"

if $COMPOSE logs --tail=100 correlator 2>/dev/null | grep -q "Cho Wazuh Indexer"; then
  bad "Correlator dang cho Indexer - ping() that bai."
  $COMPOSE logs --tail=20 correlator 2>/dev/null | grep -i "Cho Wazuh Indexer\|Khong ket noi" | tail -3 | sed 's/^/       /'
  echo
  echo "     Kiem tra truc tiep:"
  PING=$(curl_indexer -o /dev/null -w '%{http_code}' "${INDEXER_URL}/" 2>/dev/null || echo "000")
  echo "       HTTP $PING tu ${INDEXER_URL}/"
  if [[ "$PING" == "503" ]]; then
    echo "     -> 503: Indexer chua khoi tao security index."
    echo "        Chay lai buoc securityadmin.sh (README muc 3), hoac: bash scripts/deploy.sh"
  elif [[ "$PING" == "401" ]]; then
    echo "     -> 401: sai mat khau. Doi chieu .env voi internal_users.yml"
  elif [[ "$PING" == "000" ]]; then
    echo "     -> Khong ket noi duoc. Indexer chua len, hoac chua bind cong 9200."
  fi
  exit 1
fi
ok "Khong thay dau hieu mat ket noi Indexer"

# ---------------------------------------------------------------------------
step "BUOC 3: Rule tuong quan co nap du khong?"

LOADED=$($COMPOSE logs correlator 2>/dev/null | grep -o "Nap [0-9]* rule tuong quan" | tail -1 | grep -o "[0-9]*" || true)
if [[ -z "$LOADED" ]]; then
  warn "Khong tim thay dong 'Nap N rule tuong quan' trong log."
  echo "     Kiem tra mount: correlation/rules -> /app/rules"
elif [[ "$LOADED" -lt "$EXPECTED_RULES" ]]; then
  bad "Chi nap $LOADED/$EXPECTED_RULES rule. Co file YAML loi."
  echo "     load_rules() bat loi tung file roi BO QUA, engine van chay tiep"
  echo "     (correlation/siem_correlator/rules.py) - nen loi YAML khong lam correlator chet."
  $COMPOSE logs correlator 2>/dev/null | grep -i "Bo qua" | tail -5 | sed 's/^/       /'
else
  ok "Nap du $LOADED/$EXPECTED_RULES rule"
fi

# ---------------------------------------------------------------------------
step "BUOC 4: Alert co ghi duoc vao Indexer khong?"

if $COMPOSE logs --tail=200 correlator 2>/dev/null | grep -q "Ghi alert that bai"; then
  bad "Co loi khi ghi alert:"
  $COMPOSE logs --tail=200 correlator 2>/dev/null | grep "Ghi alert that bai" | tail -3 | sed 's/^/       /'
fi

COUNT=$(curl_indexer "${INDEXER_URL}/siem-correlated-*/_count?ignore_unavailable=true&allow_no_indices=true" 2>/dev/null \
        | grep -o '"count":[0-9]*' | cut -d: -f2 || echo "")
COUNT="${COUNT:-0}"

if [[ "$COUNT" -gt 0 ]]; then
  ok "Index siem-correlated-* co $COUNT document."
  echo
  warn "VAY LOI KHONG NAM O CORRELATOR - ma o phia Dashboard."
  echo "     Hai nguyen nhan, theo thu tu hay gap:"
  echo "       1. Bo loc thoi gian cua dashboard dang o khoang qua khu."
  echo "          -> Doi sang 'Last 15 minutes' roi Refresh."
  echo "       2. Chua tao index pattern 'siem-correlated-*' tren Dashboard."
  echo "          -> Dashboards Management > Index patterns > Create"
  echo "          -> Hoac import lai dashboards/siem-correlated-dashboard.ndjson"
  echo
  echo "     Ba alert tuong quan gan nhat trong Indexer:"
  curl_indexer -X POST "${INDEXER_URL}/siem-correlated-*/_search?ignore_unavailable=true" \
    -H 'Content-Type: application/json' \
    -d '{"size":3,"sort":[{"@timestamp":"desc"}],"_source":["@timestamp","correlation_rule","severity","summary"]}' \
    2>/dev/null | python -c "
import sys, json
try:
    hits = json.load(sys.stdin)['hits']['hits']
except Exception:
    sys.exit(0)
for h in hits:
    s = h['_source']
    print(f\"       {s['@timestamp'][:19]}  [{s['severity']:<8}] {s['summary']}\")
" 2>/dev/null
else
  warn "Index siem-correlated-* trong (0 document)."
  echo "     Correlator chua sinh finding nao. Sang buoc 5."
fi

# ---------------------------------------------------------------------------
step "BUOC 5: Alert Wazuh nen co - da du dieu kien cho rule tuong quan chua?"

echo "  Dem alert Wazuh 15 phut gan nhat theo rule.id:"
curl_indexer -X POST "${INDEXER_URL}/wazuh-alerts-*/_search?ignore_unavailable=true&allow_no_indices=true" \
  -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"range":{"@timestamp":{"gte":"now-15m"}}},
       "aggs":{"ids":{"terms":{"field":"rule.id","size":15}}}}' \
  2>/dev/null | python -c "
import sys, json
try:
    buckets = json.load(sys.stdin)['aggregations']['ids']['buckets']
except Exception:
    print('       (khong doc duoc ket qua)')
    sys.exit(0)
if not buckets:
    print('       KHONG co alert Wazuh nao trong 15 phut qua.')
    print('       -> Log chua toi manager. Kiem tra: gui dung IP/cong 514/udp chua?')
    sys.exit(0)
seen = {b['key']: b['doc_count'] for b in buckets}
for rid, n in sorted(seen.items(), key=lambda kv: -kv[1]):
    print(f'       {rid:<10} {n:>5}')
print()
if '100111' in seen and '100120' not in seen:
    print('       [!] Co 100111 nhung KHONG co 100120.')
    print('           Day la trieu chung dac trung cua --delay qua lon.')
    print('           Rule 100120 can 6 lan that bai/120s CUNG user CUNG IP.')
    print('           Chay lai voi: --delay 0.3')
    print()
    print('           Va vi stage 1 cua brute_force_then_success loc rule.id')
    print('           100120/100121/5710/5712/60122 - khong co 100120 thi stage 1 rong,')
    print('           nen rule tuong quan KHONG the no. Dung nguyen nhan goc.')
elif '100120' in seen or '100121' in seen:
    print('       [OK] Co alert brute force/spraying -> stage 1 da du dieu kien.')
    print('            Chi con doi correlator quet (toi da 60s).')
" 2>/dev/null

# ---------------------------------------------------------------------------
step "TOM TAT"
echo "  Neu tat ca buoc tren deu [OK] ma dashboard van trong:"
echo "    - Gan nhu chac chan la bo loc thoi gian cua dashboard (buoc 4)."
echo "  Neu buoc 5 cho thay thieu 100120: chay lai kich ban voi --delay 0.3"
echo
echo "  Xem log correlator truc tiep:"
echo "    $COMPOSE logs -f correlator"

#!/usr/bin/env bash
# Trien khai stack SIEM-raw tren mot node Docker.
# Dung tren Linux/WSL/Git Bash. Chay tu thu muc goc cua repo.
set -euo pipefail

COMPOSE_DIR="docker/single-node"
CERT_DIR="$COMPOSE_DIR/config/certs"

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "Thieu lenh: $1"; exit 1; }
}

require docker

log "Kiem tra vm.max_map_count (Wazuh Indexer yeu cau >= 262144)"
if [ -r /proc/sys/vm/max_map_count ]; then
  current=$(cat /proc/sys/vm/max_map_count)
  if [ "$current" -lt 262144 ]; then
    echo "Hien tai: $current. Chay lenh sau roi thu lai:"
    echo "  sudo sysctl -w vm.max_map_count=262144"
    echo "  (Docker Desktop tren Windows: wsl -d docker-desktop sysctl -w vm.max_map_count=262144)"
    exit 1
  fi
  echo "OK: $current"
else
  echo "Bo qua (khong doc duoc /proc/sys/vm/max_map_count)"
fi

log "Sinh chung chi TLS"
if [ -f "$CERT_DIR/root-ca.pem" ]; then
  echo "Da co chung chi, bo qua."
else
  (cd "$COMPOSE_DIR" && docker compose -f generate-certs.yml run --rm generator)
fi

log "Khoi dong stack"
(cd "$COMPOSE_DIR" && docker compose up -d)

log "Khoi tao security index cua Indexer"
# Lan dau chay, plugin security chua co index .opendistro_security nen moi request
# deu tra ve 503 "OpenSearch Security not initialized". Phai nap cau hinh bang
# securityadmin.sh. Chay lai lan sau la idempotent (ghi de cung noi dung).
INDEXER_CT="$(cd "$COMPOSE_DIR" && docker compose ps -q wazuh.indexer)"
for i in $(seq 1 30); do
  if docker exec "$INDEXER_CT" bash -c 'curl -sk https://localhost:9200 >/dev/null 2>&1'; then
    break
  fi
  printf '.'
  sleep 10
done

MSYS_NO_PATHCONV=1 docker exec "$INDEXER_CT" bash -c '
  export JAVA_HOME=/usr/share/wazuh-indexer/jdk
  /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
    -cd /usr/share/wazuh-indexer/opensearch-security/ \
    -nhnv -icl \
    -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
    -cert /usr/share/wazuh-indexer/certs/admin.pem \
    -key /usr/share/wazuh-indexer/certs/admin-key.pem \
    -h localhost -p 9200' | tail -3

log "Khoi dong lai manager va correlator de bat lai ket noi Indexer"
(cd "$COMPOSE_DIR" && docker compose restart wazuh.manager correlator)

log "Cho dich vu san sang (co the mat 2-5 phut lan dau)"
for i in $(seq 1 60); do
  if curl -sk -o /dev/null -w '%{http_code}' https://localhost:443/app/login 2>/dev/null | grep -qE '200|302'; then
    echo "Dashboard da len."
    break
  fi
  printf '.'
  sleep 10
done

cat <<'INFO'

============================================================
  SIEM-raw da chay
============================================================
  Dashboard : https://localhost   (bo qua canh bao chung chi self-signed)
  Tai khoan : admin / SecretPassword   <-- DOI NGAY trong docker/single-node/.env
  Wazuh API : https://localhost:55000
  Indexer   : https://localhost:9200

  Buoc tiep:
    1. Import dashboard:
         python dashboards/build_dashboard.py
         Dashboards Management > Saved objects > Import > siem-correlated-dashboard.ndjson
    2. Sinh log demo:
         python scripts/simulate_attack.py --scenario full
    3. Xem log correlator:
         docker compose -f docker/single-node/docker-compose.yml logs -f correlator
============================================================
INFO

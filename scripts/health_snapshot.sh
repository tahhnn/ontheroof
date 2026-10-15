#!/usr/bin/env bash
# Chup mot dong suc khoe he thong, noi vao data/results/health.log.
# Dung cho dot chay lien tuc nhieu ngay tren VPS: moi dong la mot diem do,
# 25 ngay x 48 diem/ngay = chuoi thoi gian RAM/dia/heap/so alert cho chuong 5.4,
# va RestartCount + so agent Active la bang chung do on dinh (uptime).
#
#   bash scripts/health_snapshot.sh          # chay tay, tu goc repo
#   crontab: */30 * * * * cd $HOME/SIEM-raw && bash scripts/health_snapshot.sh
#
# Moi dong dang key=value, phan tich lai bang awk/python khi viet bao cao.

set -uo pipefail

ENV_FILE="docker/single-node/.env"
OUT="data/results/health.log"
MANAGER_CT="siem-raw-wazuh.manager-1"

env_val() { grep "^$1=" "$ENV_FILE" | cut -d= -f2-; }
USER_="$(env_val INDEXER_USERNAME)"
PASS_="$(env_val INDEXER_PASSWORD)"
idx() { curl -sk -m 20 -u "${USER_}:${PASS_}" "https://127.0.0.1:9200/$1"; }
count() { idx "$1/_count?ignore_unavailable=true&allow_no_indices=true" | grep -o '"count":[0-9]*' | cut -d: -f2; }

heap=$(idx '_nodes/stats/jvm?filter_path=nodes.*.jvm.mem.heap_used_percent' \
       | grep -o '"heap_used_percent":[0-9]*' | cut -d: -f2)
agents=$(docker exec "$MANAGER_CT" /var/ossec/bin/agent_control -l 2>/dev/null | grep -c ', Active$')
# app-logge[r]: mau regex khong tu khop chinh dong lenh grep/sh nay
applogger=$(docker exec erp01 sh -c 'grep -l "app-logge[r]" /proc/[0-9]*/cmdline 2>/dev/null | wc -l' 2>/dev/null)
restarts=$(docker inspect -f '{{.Name}}:{{.State.Status}}:{{.RestartCount}}' $(docker ps -aq) 2>/dev/null \
           | sed 's#^/##' | paste -sd, -)

mkdir -p "$(dirname "$OUT")"
printf 'ts=%s disk=%s mem_mb=%s heap_pct=%s agents_active=%s app_logger=%s alerts=%s correlated=%s containers=%s\n' \
  "$(date -Is)" \
  "$(df -P / | awk 'NR==2{print $5}')" \
  "$(free -m | awk '/^Mem:/{print $3"/"$2}')" \
  "${heap:-NA}" "${agents:-NA}" "${applogger:-NA}" \
  "$(count 'wazuh-alerts-*')" "$(count 'siem-correlated-*')" \
  "${restarts:-NA}" >> "$OUT"
tail -1 "$OUT"

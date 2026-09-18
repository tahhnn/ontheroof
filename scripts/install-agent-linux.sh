#!/usr/bin/env bash
# Cai Wazuh agent 4.9.2 len may Linux (Ubuntu/Debian dung .deb, RHEL/CentOS/Rocky dung .rpm).
# Theo muc 4.3.1 cua docs/bao-cao-trien-khai.md.
#
# Cach dung (chay bang sudo/root tren may can giam sat):
#   sudo bash install-agent-linux.sh -m <IP-manager> [-n <ten-agent>] [-g <nhom>] [-p <file-goi>] [--erp]
#
# Vi du:
#   sudo bash install-agent-linux.sh -m 192.168.1.10 -n pc01
#   sudo bash install-agent-linux.sh -m 192.168.1.10 -n erp01 --erp        # may chu ERP: them khai bao doc log ung dung
#   sudo bash install-agent-linux.sh -m 192.168.1.10 -p ./wazuh-agent_4.9.2-1_amd64.deb   # cai offline tu goi co san
set -euo pipefail

WAZUH_VERSION="4.9.2-1"
DEB_URL="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}_amd64.deb"
RPM_URL="https://packages.wazuh.com/4.x/yum/wazuh-agent-${WAZUH_VERSION}.x86_64.rpm"

MANAGER=""
AGENT_NAME="$(hostname)"
AGENT_GROUP="default"
PKG_FILE=""
ERP=0

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    -m) MANAGER="$2"; shift 2 ;;
    -n) AGENT_NAME="$2"; shift 2 ;;
    -g) AGENT_GROUP="$2"; shift 2 ;;
    -p) PKG_FILE="$2"; shift 2 ;;
    --erp) ERP=1; shift ;;
    -h|--help) usage ;;
    *) echo "Tham so khong hop le: $1"; usage ;;
  esac
done

[ -n "$MANAGER" ] || { echo "Thieu -m <IP-manager> (IP may chu Wazuh trong mang noi bo)."; usage; }
[ "$(id -u)" -eq 0 ] || { echo "Phai chay bang root (sudo)."; exit 1; }

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }

# Nhan dien ho quan ly goi
if command -v dpkg >/dev/null 2>&1; then
  PKG_KIND="deb"
elif command -v rpm >/dev/null 2>&1; then
  PKG_KIND="rpm"
else
  echo "Khong tim thay dpkg hay rpm. He dieu hanh khong ho tro."; exit 1
fi

# Tai goi neu chua chi dinh file co san
if [ -z "$PKG_FILE" ]; then
  if [ "$PKG_KIND" = "deb" ]; then
    PKG_FILE="/tmp/wazuh-agent_${WAZUH_VERSION}_amd64.deb"
    URL="$DEB_URL"
  else
    PKG_FILE="/tmp/wazuh-agent-${WAZUH_VERSION}.x86_64.rpm"
    URL="$RPM_URL"
  fi
  if [ ! -f "$PKG_FILE" ]; then
    log "Tai goi cai dat: $URL"
    curl -fsSL -o "$PKG_FILE" "$URL" || { echo "Tai that bai. May khong co Internet? Copy goi sang va dung -p <file>."; exit 1; }
  fi
fi
[ -f "$PKG_FILE" ] || { echo "Khong tim thay file goi: $PKG_FILE"; exit 1; }

# Cai dat — ba bien moi truong duoc goi doc va ghi thang vao ossec.conf
log "Cai agent (manager=$MANAGER, name=$AGENT_NAME, group=$AGENT_GROUP)"
if [ "$PKG_KIND" = "deb" ]; then
  WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_AGENT_GROUP="$AGENT_GROUP" \
    dpkg -i "$PKG_FILE"
else
  WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_AGENT_GROUP="$AGENT_GROUP" \
    rpm -ihv "$PKG_FILE"
fi

# May chu ERP: them khai bao doc log ung dung truoc the </ossec_config> cuoi cung
if [ "$ERP" -eq 1 ]; then
  OSSEC_CONF="/var/ossec/etc/ossec.conf"
  if grep -q '/var/log/erpapp/app.log' "$OSSEC_CONF"; then
    echo "Da co khai bao log ERP, bo qua."
  else
    log "Them khai bao doc log ERP vao $OSSEC_CONF"
    mkdir -p /var/log/erpapp
    # Chen khoi <localfile> truoc dong </ossec_config> cuoi cung
    awk '
      { lines[NR] = $0 }
      /<\/ossec_config>/ { last = NR }
      END {
        for (i = 1; i <= NR; i++) {
          if (i == last) {
            print "  <localfile>"
            print "    <log_format>syslog</log_format>"
            print "    <location>/var/log/erpapp/app.log</location>"
            print "  </localfile>"
          }
          print lines[i]
        }
      }
    ' "$OSSEC_CONF" > "$OSSEC_CONF.tmp" && mv "$OSSEC_CONF.tmp" "$OSSEC_CONF"
    chown root:wazuh "$OSSEC_CONF" 2>/dev/null || true
  fi
fi

# Bat dich vu va cho tu khoi dong cung may
log "Khoi dong dich vu wazuh-agent"
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable --now wazuh-agent
else
  /var/ossec/bin/wazuh-control start
fi

# Kiem tra ket noi (cho toi 30 giay)
log "Kiem tra ket noi ve manager $MANAGER (cong 1514/tcp)"
for i in $(seq 1 6); do
  if grep -q "Connected to the server" /var/ossec/logs/ossec.log 2>/dev/null; then
    echo "OK: agent da ket noi manager."
    /var/ossec/bin/wazuh-control status
    echo
    echo "Xac nhan phia manager:"
    echo "  docker exec siem-raw-wazuh.manager-1 /var/ossec/bin/agent_control -l"
    exit 0
  fi
  sleep 5
done

echo "CHUA thay dong 'Connected to the server' trong /var/ossec/logs/ossec.log."
echo "Kiem tra: manager da mo cong 1514/tcp va 1515/tcp chua? IP dung chua?"
/var/ossec/bin/wazuh-control status
exit 1

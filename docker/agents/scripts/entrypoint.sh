#!/bin/bash
# Giu container song va sinh log that de Wazuh agent co cai ma doc.
set -e

echo "[entrypoint] endpoint: $(hostname)  role=${ENDPOINT_ROLE:-generic}"

# rsyslog: tao /var/log/syslog, /var/log/auth.log
# Tao san file log de Wazuh agent mo duoc ngay ca khi chua co su kien nao
touch /var/log/auth.log /var/log/syslog
# rsyslogd ha quyen xuong user "syslog"; file phai thuoc syslog:adm neu khong
# se bi "permission denied" va auth.log mai mai rong.
chown syslog:adm /var/log/auth.log /var/log/syslog
chmod 640 /var/log/auth.log /var/log/syslog
rsyslogd || echo "[entrypoint] rsyslogd khong khoi dong duoc (bo qua)"

# sshd: sinh log dang nhap that -> rule sshd co san cua Wazuh bat duoc
# -D: chay foreground; KHONG dung -e vi -e day log ra stderr,
# lam mat /var/log/auth.log ma Wazuh agent can doc.
/usr/sbin/sshd -D &

# Neu agent da duoc cai o lan chay truoc (volume /var/ossec giu lai) thi bat lai
if [ -x /var/ossec/bin/wazuh-control ]; then
    echo "[entrypoint] phat hien Wazuh agent da cai - dang khoi dong lai"
    /var/ossec/bin/wazuh-control start || true
fi

# Log ung dung ERP gia lap - trung dinh dang voi custom/decoders/local_decoder.xml
if [ "${APP_LOGGER:-off}" = "on" ]; then
    mkdir -p /var/log/erpapp
    python3 /usr/local/bin/app-logger.py >> /var/log/erpapp/app.log 2>&1 &
    echo "[entrypoint] app-logger dang ghi /var/log/erpapp/app.log"
fi

echo "[entrypoint] san sang. Cai agent bang:"
echo "  WAZUH_MANAGER='wazuh.manager' WAZUH_AGENT_NAME='$(hostname)' dpkg -i /opt/wazuh-agent.deb"
echo "  /var/ossec/bin/wazuh-control start"

tail -f /dev/null

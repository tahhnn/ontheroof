# Endpoint gia lap de cai Wazuh agent

Ba container Ubuntu 22.04 dong vai may tram / may chu trong mang doanh nghiep SMB.
Agent **khong** duoc cai san - ban tu vao container chay `dpkg -i` de thuc hanh
dung quy trinh onboarding nhu tren may that.

| Container | Vai tro | Nguon log |
|-----------|---------|-----------|
| `erp01` | May chu ung dung ERP | `/var/log/erpapp/app.log` (sinh lien tuc), `/var/log/auth.log`, `/var/log/syslog` |
| `fs01`  | May chu file noi bo  | `/var/log/auth.log`, `/var/log/syslog` |
| `pc01`  | May tram nhan vien / may nguon tan cong | `/var/log/auth.log`, `/var/log/syslog` |

## 1. Khoi dong

Stack chinh (`docker/single-node`) phai chay truoc - cac endpoint dung chung mang
`siem-raw_default` cua no de goi duoc hostname `wazuh.manager`.

```bash
docker compose -f docker/single-node/docker-compose.yml up -d
docker compose -f docker/agents/docker-compose.yml up -d --build
```

## 2. Cai agent tren tung may

```bash
docker exec -it fs01 bash

# Ba bien moi truong duoc postinst cua goi .deb doc de ghi thang vao ossec.conf
WAZUH_MANAGER='wazuh.manager' WAZUH_AGENT_NAME='fs01' WAZUH_AGENT_GROUP='default' \
  dpkg -i /opt/wazuh-agent.deb

/var/ossec/bin/wazuh-control start
/var/ossec/bin/wazuh-control status
```

Doi voi `pc01` va `erp01` lam y het, chi doi `WAZUH_AGENT_NAME`.

Goi `.deb` (4.9.2 amd64) duoc mount san tu goc repo vao `/opt/wazuh-agent.deb`,
khong can Internet.

## 3. Kiem tra da ket noi

```bash
# Phia agent
docker exec fs01 grep "Connected to the server" /var/ossec/logs/ossec.log

# Phia manager - trang thai phai la Active
docker exec siem-raw-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

Tren dashboard: **Agents management** > danh sach agent.

## 4. Rieng erp01 - doc log ung dung

Agent mac dinh khong biet file `/var/log/erpapp/app.log`. Them khoi trong
`config/erp01-localfile.xml` vao truoc the `</ossec_config>` cuoi cung cua
`/var/ossec/etc/ossec.conf` roi khoi dong lai agent:

```bash
docker cp docker/agents/config/erp01-localfile.xml erp01:/tmp/lf.xml
docker exec erp01 python3 -c "cfg='/var/ossec/etc/ossec.conf'; s=open(cfg).read(); a=open('/tmp/lf.xml').read(); i=s.rfind('</ossec_config>'); open(cfg,'w').write(s[:i]+a+s[i:])"
docker exec erp01 /var/ossec/bin/wazuh-control restart
docker exec erp01 grep "Analyzing file" /var/ossec/logs/ossec.log
```

Sau ~30 giay se thay alert rule 100110/100111... trong index `wazuh-alerts-*`
voi `agent.name: erp01`.

### Log nen sinh nhu the nao

`scripts/app-logger.py` khong random tung dong roi rac. No mo phong mot doanh
nghiep 7 nguoi:

- **Danh tinh co dinh**: moi nhan vien co mot tai khoan, mot may tram (IP co
  dinh trong `192.168.10.0/24`), mot bo module duoc phep xuat. Nguoi lam viec tu
  xa duoc cap them dung MOT IP VPN co dinh.
- **Phien lam viec**: dang nhap (doi khi go sai mat khau 1-2 lan) roi mot chuoi
  10-30 thao tac nghiep vu rai rac trong 20-90 phut, dung theo vai tro (thu kho
  nhap xuat kho, ke toan chot hoa don, ban hang tao don).
- **Nhip ngay lam viec** theo gio VN: cao diem 08:00-11:30 va 13:15-17:00, vang
  gio trua, gan tat sau 21:00, thu bay nua ngay, chu nhat gan nhu khong co ai.
  Ban dem chi co tac vu `svc_batch` chay tren may chu, **khong co su kien AUTH**.
- **Tuyet doi khong sinh bao dong sai**: moi nguong trong script nam duoi dieu
  kien cua rule that. Xem khoi `HANG RAO` dau file.

Kiem chung lai bang dong ho ao (khong can stack, khong ghi log):

```bash
python3 docker/agents/scripts/app-logger.py --audit 30
```

Ket qua phai la `log nen khong kich hoat rule tan cong nao`. Neu sua bang nhan
su / trong so trong script, chay lai lenh nay truoc khi dung.

Cac tham so dieu chinh khi demo:

| Tham so | Y nghia |
|---------|---------|
| `--rate 3` (`APP_LOGGER_RATE`) | tang nhip su kien x3 khi can du lieu nhanh |
| `--seed 42` (`APP_LOGGER_SEED`) | tai lap dung chuoi log (dung khi so sanh truoc/sau) |
| `--always-business` (`APP_LOGGER_ALWAYS_BUSINESS=1`) | bo qua nhip ngay/dem de thu luc dem. CANH BAO: chay ngoai T2-T6 07:30-17:30 gio VN se sinh rule 100122/100123 "dang nhap ngoai gio" khong dung y nghia |

## 5. Sinh su kien de kiem thu

```bash
# Brute-force SSH tu pc01 vao fs01 -> rule sshd co san cua Wazuh (5710, 5712)
docker exec pc01 bash -c 'for i in $(seq 1 10); do \
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 ketoan1@fs01 exit; done'

# Chuoi tan cong ung dung ERP (syslog UDP thang vao manager, khong qua agent)
python scripts/simulate_attack.py --host 127.0.0.1 --scenario full
```

## 6. Ghi chu ky thuat

- Container **khong co systemd**. Dung `/var/ossec/bin/wazuh-control start|stop|status|restart`,
  khong dung `systemctl`.
- Thu muc `/var/ossec` cua moi may nam tren named volume rieng, nen agent da cai
  van con sau khi `docker compose restart`. Entrypoint tu bat lai agent neu thay
  `/var/ossec/bin/wazuh-control`.
- Muon lam lai tu dau: `docker compose -f docker/agents/docker-compose.yml down -v`
  (xoa ca volume), roi go agent tren manager bang
  `/var/ossec/bin/manage_agents -r <id>`.
- `sshd` chay khong co co `-e` de log di vao syslog thay vi stderr; file
  `/var/log/auth.log` duoc tao san va chown `syslog:adm`, neu khong rsyslogd
  (chay duoi user `syslog`) se khong ghi duoc.

## 7. Loi da gap: agent chet sau khi recreate container

Trieu chung: `execd: CRITICAL (1203): Invalid user '' or group 'wazuh'` va
`agentd: CRITICAL (1103): Could not open file 'queue/rids/...' Permission denied`.

Nguyen nhan: postinst goi `.deb` tao user OS `wazuh` (uid 103 / gid 104) vao lop
ghi cua container, nhung `/var/ossec` nam tren named volume. Khi container bi
**recreate** (`compose up --build`), file agent con nguyen thuoc 103:104 nhung
user OS bi mat -> agent khong start.

Da fix trong Dockerfile: tao san `wazuh` uid 103 / gid 104 o tang image nen luon
khop. Neu van gap tren container cu:

```bash
docker exec <may> bash -c "groupadd -g 104 wazuh; useradd -u 103 -g 104 -d /var/ossec -s /sbin/nologin wazuh"
docker exec <may> /var/ossec/bin/wazuh-control restart
```

## 8. Bat FIM realtime cho kich ban leo thang quyen

Rule tuong quan `privilege_then_config_change` can FIM bao NGAY khi file cau hinh
doi (mac dinh Wazuh chi quet dinh ky 12h). Chen `config/fim-realtime.xml` vao
`<syscheck>` cua agent, ngay sau dong `<directories>/etc,/usr/bin,/usr/sbin</directories>`:

```bash
docker exec <may> bash -c '
  grep -q "/etc/erpapp" /var/ossec/etc/ossec.conf || \
  sed -i "s|<directories>/etc,/usr/bin,/usr/sbin</directories>|&\n    <directories realtime=\"yes\" check_all=\"yes\" report_changes=\"yes\">/etc/erpapp</directories>|" /var/ossec/etc/ossec.conf'
docker exec <may> /var/ossec/bin/wazuh-control restart
docker exec <may> grep "Directory set for real time" /var/ossec/logs/ossec.log
```

CANH BAO: dung `sed` thay `<disabled>no</disabled>` se chen sai vi chuoi do co o
nhieu module (rootcheck, sca...). Phai neo vao dong `<directories>/etc,...` (chi co
trong `<syscheck>`).

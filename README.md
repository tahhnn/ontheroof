# SIEM-raw

Đồ án tốt nghiệp: **Triển khai hệ thống giám sát an ninh (SIEM) cho doanh nghiệp vừa và nhỏ**.

Nền tảng: **Wazuh 4.x** chạy Docker một node, bổ sung **decoder/rule tự viết** cho ứng dụng nội bộ và một **engine tương quan sự kiện (correlation)** viết bằng Python để phát hiện chuỗi tấn công mà rule Wazuh đơn lẻ không bắt được.

---

## 1. Kiến trúc

```
┌──────────────────────────────┐
│  Nguồn log của doanh nghiệp  │
│  • Agent Windows / Linux     │──── TCP 1514 ───┐
│  • Router / firewall (syslog)│──── UDP 514  ───┤
│  • Ứng dụng ERP nội bộ       │──── UDP 514  ───┤
└──────────────────────────────┘                 │
                                                 ▼
                                    ┌────────────────────────┐
                                    │     Wazuh Manager      │
                                    │  decoder + ruleset     │
                                    │  (có custom của đồ án) │
                                    └───────────┬────────────┘
                                                │ Filebeat
                                                ▼
                                    ┌────────────────────────┐        ┌──────────────────┐
                                    │    Wazuh Indexer       │◄───────│   Correlator     │
                                    │  wazuh-alerts-*        │ đọc    │  (Python)        │
                                    │  siem-correlated-*     │◄───────│  ghi alert tương │
                                    └───────────┬────────────┘ ghi    │  quan            │
                                                │                     └──────────────────┘
                                                ▼
                                    ┌────────────────────────┐
                                    │   Wazuh Dashboard      │
                                    │  https://localhost     │
                                    └────────────────────────┘
```

Ba lớp phát hiện:

| Lớp | Ở đâu | Phát hiện được gì | Giới hạn |
|-----|-------|-------------------|----------|
| Rule Wazuh có sẵn | manager | Tấn công đã biết trên OS, dịch vụ phổ biến | Không hiểu log ứng dụng riêng |
| Decoder + rule tự viết | `custom/` | Sự kiện của ứng dụng ERP nội bộ | Cửa sổ tương quan ngắn, một nguồn log |
| Engine correlation | `correlation/` | Chuỗi hành vi qua nhiều nguồn log, cửa sổ tới vài giờ | Chạy theo chu kỳ (mặc định 60s), không realtime |

---

## 2. Yêu cầu

- Docker Engine + Docker Compose v2
- RAM ≥ 6 GB cấp cho Docker (Indexer mặc định 1 GB heap)
- Ổ đĩa trống ≥ 20 GB
- `vm.max_map_count >= 262144`

```bash
sudo sysctl -w vm.max_map_count=262144
```

Trên Docker Desktop/Windows:

```bash
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

---

## 3. Triển khai

```bash
bash scripts/deploy.sh
```

Hoặc làm thủ công:

```bash
cd docker/single-node
docker compose -f generate-certs.yml run --rm generator
docker compose up -d
```

Nếu làm thủ công, **bắt buộc** chạy thêm bước khởi tạo security index của Indexer, nếu không mọi request đều trả về `OpenSearch Security not initialized` (HTTP 503) và không đăng nhập được:

```bash
docker exec siem-raw-wazuh.indexer-1 bash -c 'export JAVA_HOME=/usr/share/wazuh-indexer/jdk; /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -icl -cacert /usr/share/wazuh-indexer/certs/root-ca.pem -cert /usr/share/wazuh-indexer/certs/admin.pem -key /usr/share/wazuh-indexer/certs/admin-key.pem -h localhost -p 9200'
```

`scripts/deploy.sh` đã bao gồm bước này. Chi tiết các lỗi hay gặp: [docs/so-tay-van-hanh.md](docs/so-tay-van-hanh.md) mục 8.

Truy cập `https://localhost` — tài khoản `admin` / `SecretPassword`.

> **Đổi mật khẩu trước khi dùng thật.** Mật khẩu mặc định nằm trong `docker/single-node/.env` và hash bcrypt trong `config/wazuh_indexer/internal_users.yml`. Sinh hash mới bằng công cụ `hash.sh` của plugin security trong container indexer.

---

## 4. Cài agent lên máy trạm

Trên endpoint cần giám sát (thay `<IP-manager>`):

```bash
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb
sudo WAZUH_MANAGER='<IP-manager>' dpkg -i ./wazuh-agent_4.9.2-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```

Windows: tải MSI từ trang tải Wazuh rồi cài với biến `WAZUH_MANAGER`.

Thiết bị không cài được agent (router, switch, NAS, firewall): trỏ syslog về `<IP-manager>:514/udp`. Dải IP được phép nhận syslog khai báo trong `docker/single-node/config/wazuh_manager/ossec.conf`.

---

## 5. Decoder và rule tự viết

| File | Nội dung |
|------|----------|
| `custom/decoders/local_decoder.xml` | Bóc tách log ứng dụng ERP nội bộ (`erpapp`): đăng nhập, xuất dữ liệu, cấp quyền, sửa giá đơn hàng |
| `custom/rules/local_rules.xml` | Rule 100100–100903 |

Các rule chính:

| ID | Mức | Phát hiện |
|----|-----|-----------|
| 100101 / 100102 | 2 / 7 | Dòng log `erpapp` không decode được / nhiều dòng hỏng trong 300s — chuông báo decoder mù |
| 100110 / 100111 | 3 / 5 | Đăng nhập thành công / thất bại |
| 100120 | 10 | Brute force (6 lần thất bại / 120s cùng IP) |
| 100121 | 10 | Password spraying (1 IP thử nhiều tài khoản) |
| 100122 / 100123 | 6 | Đăng nhập ngoài giờ hành chính (trước 07:30 / từ 17:30 T2–T6, cả ngày T7–CN, giờ VN) — `<time>`/`<weekday>` ghi theo **UTC**, xem lưu ý 6 |
| 100130 / 100131 | 5 / 10 | Xuất dữ liệu nhạy cảm / xuất hàng loạt ≥ 10000 dòng |
| 100140 / 100141 | 8 / 12 | Cấp quyền / cấp quyền **admin** |
| 100150 | 7 | Sửa giá đơn hàng (gian lận nghiệp vụ) |
| 100200 | 2 | Rule gốc firewall — **level 2 chứ không phải 0**, xem mục lưu ý dưới bảng |
| 100220 | 10 | Quét cổng (15 lần bị firewall chặn / 60s) |
| 100901–100903 | 10–14 | Alert do engine correlation sinh ra |

Bảy điểm đã vấp phải khi viết decoder/rule, đều đã sửa trong repo:

1. **Decoder con phải có `<prematch>`.** Bốn decoder `erpapp-*` dùng chung một parent. Thiếu
   `<prematch>`, chỉ decoder con **đầu tiên** (`erpapp-auth`) hoạt động — EXPORT/PERM/TXN
   không bóc được trường nào nên rule 100130/100131/100140/100141/100150 không bao giờ nổ.
2. **Rule gốc của chuỗi tần suất không được để `level 0`.** Rule 100220 đếm qua
   `<if_matched_sid>100200</if_matched_sid>`; analysisd không lưu sự kiện của rule level 0 vào
   danh sách đối chiếu tần suất. Đặt 100200 ở `level 2` — nhỏ hơn `log_alert_level` (3) trong
   `ossec.conf` nên vẫn không ghi alert, không gây nhiễu.
3. **Hai rule cùng nghe một `if_matched_sid` sẽ tranh nhau.** 100120 và 100121 cùng đếm trên
   100111; analysisd dừng ở rule đầu tiên khớp nên 100120 ăn hết sự kiện. Thêm `<same_user />`
   vào 100120 để tách ngữ nghĩa: brute force = cùng một tài khoản, spraying = nhiều tài khoản.
4. **So khớp không neo `^...$` là so khớp chuỗi con.** `<status>OK</status>` khiến
   `result=NOTOK`, `TOKEN_EXPIRED`, `BLOCKED` đều lọt vào rule "đăng nhập thành công" — rule
   tương quan `brute_force_then_success` khi đó kết luận ngược: tấn công bị khóa tài khoản lại
   bị báo là đã chiếm được tài khoản. Đã đổi thành `^OK$` / `^FAILED$`.
5. **os_regex mặc định không hiểu lớp ký tự `[1-9]`.** Rule không báo lỗi khi nạp nhưng không
   bao giờ khớp. Ngưỡng ≥ 10000 dòng của 100131 phải viết `type="pcre2"` với
   `^[1-9][0-9]{4,}$`; regex cũ `^\d\d\d\d\d+$` chỉ **đếm số chữ số** nên `rows=00012`
   (12 dòng) vẫn bị báo "xuất dữ liệu hàng loạt" mức 10.
6. **`<time>` so theo giờ UTC, không theo múi giờ container.** Đã thử cả `TZ` trong compose lẫn
   ghi đè `/etc/localtime`: `ossec.log` chuyển sang `+07` nhưng `<time>` vẫn dùng UTC. Khung giờ
   phải tự trừ 7 tiếng. Trước khi trừ, rule 100122 bắt đúng 09:00–12:00 giờ VN và đã sinh 469
   cảnh báo sai. `<weekday>` cũng theo UTC: 00:00–06:59 giờ VN thuộc ngày hôm trước theo UTC.
   Giờ làm việc T2–T6 07:30–17:00 giờ VN, cộng 30 phút ra về → trong giờ = 07:30–17:30 giờ VN
   = 00:30–10:30 UTC, nằm gọn trong **một** ngày UTC, nên thứ UTC trùng thứ VN trong giờ làm và
   chỉ cần 2 rule: 100122 (`weekdays`, `10:30 - 00:30`)
   và 100123 (`weekends`, cả ngày). Nếu giờ vào làm sớm hơn 07:00 giờ VN, khung sẽ vắt qua nửa
   đêm UTC và phải tách rule theo ngày.
7. **analysisd thử các rule anh em theo level giảm dần, không theo thứ tự trong file.** Rule
   bắt lỗi decoder 100101 phải để `level 2`; để level 5 thì nó được thử trước 100110 (level 3)
   và nuốt hết log đăng nhập hợp lệ.

Kiểm thử decoder/rule:

```bash
bash scripts/test_rules.sh
```

Sau khi sửa file trong `custom/`, nạp lại ruleset:

```bash
docker compose -f docker/single-node/docker-compose.yml restart wazuh.manager
```

---

## 6. Engine tương quan

Mã nguồn: `correlation/siem_correlator/`. Rule khai báo bằng YAML trong `correlation/rules/`.

Ba kiểu rule:

- `threshold` — đếm alert theo khoá (`group_by`) trong cửa sổ thời gian.
- `distinct` — đếm số giá trị **khác nhau** của một trường theo khoá (ví dụ: một tài khoản đăng nhập từ ≥ 3 IP).
- `sequence` — nhiều giai đoạn phải xảy ra **đúng thứ tự** trên cùng một khoá join.

Ví dụ một rule chuỗi tấn công:

```yaml
- id: account_takeover_to_exfil
  name: Chiem tai khoan roi xuat du lieu
  type: sequence
  severity: critical
  window: 3600
  join_field: data.dstuser
  stages:
    - name: bi_do_mat_khau
      filter: { rule.id: ["100111"] }
      min_count: 3
    - name: dang_nhap_thanh_cong
      filter: { rule.id: ["100110"] }
    - name: xuat_du_lieu
      filter: { rule.id: ["100130", "100131"] }
  summary: "Tai khoan {key}: bi do mat khau -> dang nhap thanh cong -> xuat du lieu"
```

Alert sinh ra được ghi vào index `siem-correlated-YYYY.MM.DD` với `_id` tất định — chạy lại cùng cửa sổ sẽ ghi đè chứ không nhân bản alert.

Chạy thử ngoài container (in ra màn hình, không ghi gì):

```bash
cd correlation
INDEXER_URL=https://localhost:9200 INDEXER_PASSWORD=SecretPassword python -m siem_correlator --once --dry-run
```

Chạy unit test (không cần Indexer):

```bash
python correlation/tests/test_engine.py
```

Biến môi trường: `INDEXER_URL`, `INDEXER_USERNAME`, `INDEXER_PASSWORD`, `INDEXER_VERIFY_CERTS`, `ALERTS_INDEX`, `OUTPUT_INDEX_PREFIX`, `RULES_PATH`, `POLL_INTERVAL`, `LOG_LEVEL`, `MANAGER_SOCKET`.

Nếu muốn alert tương quan đi ngược qua ruleset Wazuh (để dùng active response, gửi email), mount socket của manager vào container correlator và đặt `MANAGER_SOCKET=/var/ossec/queue/sockets/queue`; rule 100900–100903 sẽ bắt các alert này.

---

## 7. Dashboard

```bash
python dashboards/build_dashboard.py
```

Import file `dashboards/siem-correlated-dashboard.ndjson` qua **Dashboards Management → Saved objects → Import**.

Dashboard gồm: tổng số alert tương quan, phân bố theo mức độ, biểu đồ theo thời gian, top rule kích hoạt, top đối tượng bị cảnh báo, bảng alert mức critical.

---

## 8. Demo kịch bản tấn công

```bash
python scripts/simulate_attack.py --scenario full
```

Chín kịch bản:

| Kịch bản | Mô phỏng | Alert kỳ vọng |
|----------|----------|----------------|
| `bruteforce` | 8 lần sai mật khẩu cùng một tài khoản | 100111, 100120 |
| `spray` | 1 IP thử lần lượt 10 tài khoản khác nhau | 100111, 100121 |
| `exfil` | Xuất dữ liệu hàng loạt | 100130, 100131, `mass_data_export_by_user` |
| `portscan` | 20 lần bị firewall chặn trong vài giây | 100200, 100220 |
| `scan-then-login` | Quét cổng rồi chuyển sang dò mật khẩu | 100220 + `scan_then_login_attempt` |
| `impossible-travel` | Một tài khoản đăng nhập thành công từ 4 IP | 100110 + `impossible_travel` |
| `insider` | Nhân viên đăng nhập hợp lệ rồi lấy dữ liệu, sửa giá | 100131, 100150 + `mass_data_export_by_user` |
| `full` | Dò mật khẩu → vào được → tự cấp quyền admin → xuất dữ liệu → sửa giá | 100120, 100141, 100131, 100150 + `brute_force_then_success`, `account_takeover_to_exfil` |
| `all` | Chạy lần lượt tất cả kịch bản trên (70 sự kiện) | toàn bộ |

Script in ra danh sách alert kỳ vọng ngay khi chạy.

Kịch bản `portscan` và `scan-then-login` sinh log định dạng iptables với tag syslog `kernel`
(host `fw01`), dùng decoder có sẵn của Wazuh — khác nguồn với log ứng dụng ERP.

> **`--delay` phải ≤ 1.0.** Rule tần suất của Wazuh có cửa sổ cố định (brute force 6 lần/120s,
> quét cổng 15 lần/60s). Để delay lớn hơn thì sự kiện tràn ra ngoài cửa sổ và rule không kích hoạt.

Kiểm chứng kết quả:

1. Wazuh Dashboard → Threat Hunting: alert 100111, 100120, 100131, 100141.
2. Dashboard "SIEM-raw - Alert tương quan": alert `brute_force_then_success`, `account_takeover_to_exfil`.
3. Log correlator: `docker compose -f docker/single-node/docker-compose.yml logs -f correlator`.

---

## 9. Cấu trúc thư mục

```
SIEM-raw/
├── docker/single-node/       # Docker Compose + config Wazuh
├── custom/                   # Decoder + rule tự viết
├── correlation/              # Engine tương quan (Python) + rule YAML + test
├── dashboards/               # Script sinh saved objects + file NDJSON
├── scripts/                  # deploy, test rule, giả lập tấn công
├── data/sample-logs/         # Log mẫu
└── docs/                     # Báo cáo, sổ tay vận hành
```

---

## 10. Lưu ý bảo mật

- Mật khẩu và chứng chỉ trong repo là giá trị demo. Không dùng nguyên trạng cho môi trường thật.
- `docker/single-node/config/certs/` chứa khoá riêng — đã bị loại khỏi Git trong `.gitignore`.
- Cổng 9200 và 55000 mở ra host để tiện phát triển; khi triển khai thật nên chỉ bind `127.0.0.1`.
- Dải IP được phép gửi syslog phải thu hẹp đúng LAN của doanh nghiệp, tránh nhận log giả mạo từ ngoài.

---

## 11. Chuẩn bị bảo vệ

| Tài liệu | Nội dung |
|----------|----------|
| [docs/bao-ve-hoi-dong.md](docs/bao-ve-hoi-dong.md) | Trả lời 20 câu phản biện + 7 tình huống, có nhãn *đã kiểm chứng / suy luận / chưa kiểm chứng* |
| [docs/kich-ban-hoi-dong.md](docs/kich-ban-hoi-dong.md) | Bảng tra script theo từng tình huống, thứ tự diễn tập |

Script bổ sung cho phần kiểm thử và đánh giá:

| Script | Dùng để |
|--------|---------|
| `scripts/benign_traffic.py` | Sinh lưu lượng **lành tính** để đo false positive; `--storm` tái hiện bão alert |
| `scripts/eval_detection.py` | Đo Recall, Precision, F1, FP/ngày — bộ chỉ số cho chương đánh giá |
| `scripts/evade_thresholds.py` | Kẻ tấn công biết ngưỡng và chạy dưới ngưỡng; có chế độ đối chứng `--loud` |
| `scripts/slow_insider.py` | Nội gián lấy dữ liệu đều đặn 60 ngày — chứng minh giới hạn kiến trúc |
| `scripts/negative_rule_test.sh` | Kiểm thử **âm tính** tự động (log nào **không được** khớp rule nào) |
| `scripts/troubleshoot_demo.sh` | Chẩn đoán 5 bước khi dashboard tương quan trống lúc demo |
| `scripts/measure_capacity.sh` | Đo EPS, dung lượng/ngày, heap JVM; ngoại suy cho N endpoint |

`negative_rule_test.sh` thoát mã 1 khi có ca sai nên cắm được vào CI. Khác `test_rules.sh` ở chỗ
kỳ vọng là **dữ liệu được so tự động**, không phải comment đọc bằng mắt — đúng loại kiểm thử bắt
được lỗi `^OK$` ở lưu ý 4 mục 5.

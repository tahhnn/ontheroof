# Giáo trình hiểu hệ thống — đọc để bảo vệ được, không phải để chạy được

> Tài liệu này khác `docs/bao-ve-hoi-dong.md`. Tài liệu kia là **bộ đề** (20 câu hỏi
> phản biện kèm đáp án). Tài liệu này là **giáo trình**: giải thích từ nguyên lý,
> bám đúng code trong repo, để khi hội đồng hỏi lệch khỏi bộ đề thì vẫn tự suy ra được.

Quy ước nhãn (giữ nguyên quy ước của `docs/bao-ve-hoi-dong.md`):

- **[Đã kiểm chứng]** — đọc trực tiếp từ code/config trong repo, có dẫn file:dòng.
- **[Suy luận]** — kết luận logic rút ra từ code, chưa chạy thực nghiệm xác nhận.
- **[Chưa kiểm chứng]** — cần đo mới khẳng định được.

## Cách đọc

Mỗi chương có 3 phần cố định:

1. **Nguyên lý** — cái này là gì, hoạt động thế nào.
2. **Trong repo này** — code cụ thể, vì sao viết như vậy.
3. **Tự kiểm tra** — câu hỏi phải trả lời được khi gấp laptop.

Đọc xong một chương, làm phần 3 trước khi sang chương sau. Không trả lời được thì
đọc lại, đừng đọc tiếp.

Thứ tự đề nghị: **Chương 0 → 1 → 2 → 3 → 4 → 5 → 6**, rồi Chương 7 để biết repo yếu ở đâu.
Chương 0 là bản đồ — không đọc nó thì sáu chương sau rời rạc. Nếu gấp, ưu tiên
**Chương 0 → 3 → 4**: bản đồ, phần tự viết nhiều nhất, và cách đọc số liệu.

---

# CHƯƠNG 0 — Luồng log thực tế trong hệ thống này

Đọc chương này **trước tiên**. Sáu chương sau đều nói về một chặng nào đó của luồng này;
không có bản đồ thì đọc chi tiết sẽ rời rạc.

Mục tiêu: truy được một dòng log từ lúc sinh ra tới lúc hiện trên dashboard, **gọi đúng
tên từng tiến trình, từng cổng, từng file**.

## 0.1 Bản đồ tổng thể

```
   NGUỒN                    MANAGER                      INDEXER        DASHBOARD
   ─────                    ───────                      ───────        ─────────

 endpoint ──agent──┐
 (1514/tcp)        │
                   ├──► wazuh-remoted ──► wazuh-analysisd ──► alerts.json
 firewall ─syslog──┘      (nhận)            (decode+rule)          │
 (514/udp)                                                         │
                                                              filebeat
                                                                   │  TLS
                                                                   ▼
                                                        wazuh-alerts-*  ──┐
                                                                   ▲      │
                                                        query 60s  │      ├──► UI
                                                                   │      │
                                                          correlator      │
                                                        (Python, engine)  │
                                                                   │      │
                                                                   ▼      │
                                                      siem-correlated-* ──┘
```

Điểm quan trọng nhất của sơ đồ này, và cũng là câu dễ bị hỏi:

> **Correlator không nằm trên đường đi của log.** Nó không nhận log, không chặn log,
> không nối tiếp vào chuỗi xử lý. Nó đứng bên cạnh, **đọc lại** alert đã lưu trong
> Indexer rồi ghi kết quả vào một index khác.

Hệ quả kiến trúc của lựa chọn này:

| Hệ quả | Chi tiết |
|---|---|
| Correlator chết thì hệ thống vẫn chạy | mất lớp 3, lớp 1–2 nguyên vẹn |
| Không realtime | MTTD của lớp 3 tối đa bằng `POLL_INTERVAL` = 60 giây |
| Không cần message broker | không Kafka, không Redis — kiến trúc gọn cho SME |
| Tương quan chỉ thấy được **alert**, không thấy sự kiện thô | sự kiện level < 3 không lên Indexer nên engine không thấy |

Dòng cuối là chi tiết quan trọng mà ít người để ý: **engine tương quan không nhìn thấy
log, nó chỉ nhìn thấy alert**. Sự kiện bị Wazuh cho là bình thường (level < 3) sẽ không
bao giờ đến được lớp 3.

## 0.2 Truy vết một dòng log ERP — 10 chặng

Lấy đúng một dòng, đi hết đường.

### Chặng 1 — Sinh log

`scripts/simulate_attack.py` đóng khung theo syslog RFC3164 rồi gửi UDP:

```python
def syslog_line(ev: Event) -> str:
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    # PRI 13 = facility 1 (user), severity 5 (notice)
    return f"<13>{ts} {ev.host} {ev.tag}: {ev.message}"
```

Gói tin trên dây:

```
<13>Sep 21 14:32:10 erp01 erpapp: AUTH result=FAILED user=nvhung srcip=192.168.10.24 reason=bad_password path=/api/login
```

Bốn phần, mỗi phần có vai riêng:

| Phần | Giá trị | Ai dùng nó |
|---|---|---|
| `<13>` | PRI = facility 1 × 8 + severity 5 | bộ tiền xử lý syslog |
| `Sep 21 14:32:10` | timestamp | bộ tiền xử lý |
| `erp01` | hostname | thành `agent.name` / `manager.name` trong alert |
| `erpapp` | tag | **thành `program_name`** — đây là thứ decoder cha khớp |
| phần còn lại | message | phần decoder con bóc |

[Đã kiểm chứng — `scripts/simulate_attack.py`, hàm `syslog_line`]

**Trong thực tế** chặng này là ứng dụng ERP ghi ra syslog. Trong lab là script. Đây chính
là mắt xích tạo ra kiểm chứng vòng tròn (Chương 4, mục 4.5).

### Chặng 2 — Nhận: `wazuh-remoted`, cổng 514/udp

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>172.16.0.0/12</allowed-ips>
  <allowed-ips>192.168.0.0/16</allowed-ips>
  <allowed-ips>10.0.0.0/8</allowed-ips>
</remote>
```

`wazuh-remoted` lọc theo IP nguồn. Gói từ IP ngoài ba dải này bị **bỏ im lặng**.

Cổng ánh xạ ra host qua `"514:514/udp"` trong compose.

**Chỗ thường vấp:** chạy `simulate_attack.py` từ máy host thì IP nguồn là IP gateway của
Docker (thường thuộc `172.16.0.0/12`) nên lọt. Chạy từ một máy khác trong dải lạ thì
gói bị bỏ mà **không có log nào báo** — đây là điểm mù chẩn đoán đầu tiên.

### Chặng 3 — Hàng đợi

```xml
<global>
  <queue_size>131072</queue_size>
</global>
```

Sự kiện vào hàng đợi trước khi `wazuh-analysisd` xử lý. Hàng đầy thì sự kiện **bị vứt**
và manager ghi cảnh báo trong `ossec.log`.

Đây là con số cần nhắc khi hội đồng hỏi về giới hạn EPS: nút thắt không phải ở mạng mà ở
tốc độ `analysisd` xử lý so với tốc độ log đổ vào.

### Chặng 4 — Tiền xử lý (pre-decoding)

`wazuh-analysisd` tách phần khung syslog **trước khi** decoder tự viết được gọi:

```
timestamp    = Sep 21 14:32:10
hostname     = erp01
program_name = erpapp
message      = AUTH result=FAILED user=nvhung srcip=...
```

[Suy luận — đây là hành vi chuẩn của `analysisd` với log syslog; repo không chứa mã nguồn
Wazuh nên không kiểm chứng trực tiếp được, nhưng quan sát được gián tiếp qua việc decoder
cha chỉ cần khớp `<program_name>^erpapp$</program_name>`]

Đây là lý do decoder cha **không** phải viết regex cho phần `Sep 21 14:32:10 erp01`.

### Chặng 5 — Decode

```
decoder "erpapp"        khớp program_name ^erpapp$        → mở cổng
decoder "erpapp-auth"   prematch ^AUTH  (after_parent)    → xác nhận loại
                        regex bóc 5 nhóm                  → gán theo <order>
```

Kết quả sau chặng này — dòng chữ đã thành dữ liệu có cấu trúc:

```
status  = FAILED        (trường tĩnh)
dstuser = nvhung        (trường tĩnh)
srcip   = 192.168.10.24 (trường tĩnh)
erp.reason = bad_password (trường động)
url     = /api/login    (trường tĩnh)
```

Chi tiết: Chương 1.

**Nếu regex trượt:** không có trường nào được bóc, sự kiện vẫn đi tiếp sang chặng 6 nhưng
chỉ khớp được rule 100100. Đây chính là tình huống mà chuỗi rule 100101–100106 được thiết
kế để bắt (Chương 2, mục 2.2 (5)).

### Chặng 6 — Khớp rule

```
100100 (level 0)  ← decoded_as erpapp            : khớp, nhưng level 0, không ghi alert
100111 (level 5)  ← if_sid 100100 + status ^FAILED$ : KHỚP → đây là alert
```

Đồng thời `analysisd` **ghi nhớ** sự kiện này vào danh sách đối chiếu tần suất, phục vụ
hai rule trạng thái:

- `100120` (brute force) — `if_matched_sid 100111`, `frequency=6`, `timeframe=120`,
  cùng IP **và** cùng user
- `100121` (spraying) — `if_matched_sid 100111`, `frequency=8`, `timeframe=300`,
  cùng IP nhưng **khác** user

Nếu dòng log này là dòng thứ 6 từ cùng IP lên cùng tài khoản trong 120 giây, rule 100120
nổ **thêm một alert nữa** ở level 10 — và alert đó kích hoạt active response `firewall-drop`
(timeout 600 giây) [Đã kiểm chứng — `ossec.conf`, khối `<active-response>` liệt kê
`<rules_id>100120,100220</rules_id>`].

**Một dòng log có thể sinh nhiều hơn một alert.** Chi tiết này quan trọng khi đếm FP.

### Chặng 7 — Ghi ra đĩa

```xml
<global>
  <jsonout_output>yes</jsonout_output>
  <alerts_log>yes</alerts_log>
  <logall>no</logall>
  <logall_json>no</logall_json>
</global>
<alerts>
  <log_alert_level>3</log_alert_level>
</alerts>
```

[Đã kiểm chứng — `docker/single-node/config/wazuh_manager/ossec.conf`]

Alert level 5 ≥ ngưỡng 3 → được ghi vào **hai** file trong container manager:

| File | Định dạng | Ai đọc |
|---|---|---|
| `/var/ossec/logs/alerts/alerts.json` | JSON, một alert một dòng | **filebeat** |
| `/var/ossec/logs/alerts/alerts.log` | văn bản cho người đọc | người, khi gỡ lỗi |

Ba điểm phải hiểu ở chặng này:

1. **`log_alert_level` 3 là cái van.** Level 0–2 không bao giờ ra khỏi manager. Đây là lý
   do rule 100200 phải để level 2 chứ không phải 0 (Chương 2) — đủ để được đếm tần suất
   nội bộ, không đủ để chiếm chỗ trên đĩa.
2. **`logall no`** — log thô **không** được lưu. Chỉ alert mới được lưu. Tiết kiệm đĩa rất
   nhiều, nhưng đánh đổi: **không điều tra ngược được** trên sự kiện chưa thành alert.
   Đây là một hạn chế thật, nên nêu ở chương 6.2 của báo cáo.
3. Thư mục này nằm trên named volume `wazuh_logs` → sống sót qua `docker compose restart`,
   mất khi `docker compose down -v`.

### Chặng 8 — Filebeat đẩy lên Indexer

Filebeat chạy **bên trong container manager** (không phải container riêng), theo dõi
`alerts.json`, đẩy từng dòng sang Indexer qua TLS:

```yaml
INDEXER_URL: https://wazuh.indexer:9200
FILEBEAT_SSL_VERIFICATION_MODE: full
SSL_CERTIFICATE_AUTHORITIES: /etc/ssl/root-ca.pem
SSL_CERTIFICATE: /etc/ssl/filebeat.pem
SSL_KEY: /etc/ssl/filebeat.key
```

[Đã kiểm chứng — `docker-compose.yml`, khối `wazuh.manager`]

Đây là đường **xác thực hai chiều bằng chứng chỉ**, chế độ verify `full`. Đối chiếu với
correlator đặt `INDEXER_VERIFY_CERTS: "false"` — chỗ không nhất quán đã nêu ở Chương 7,
mục 7.5.

Alert đi vào index tên dạng `wazuh-alerts-4.x-YYYY.MM.DD`
[Suy luận — cấu hình filebeat nằm trong image Wazuh, không có trong repo; suy ra từ việc
mọi truy vấn trong repo đều dùng mẫu `wazuh-alerts-*`].

Cấu trúc một alert sau chặng này — đây là **hình dạng dữ liệu mà rule tương quan làm việc
trên đó**, phải thuộc:

```json
{
  "@timestamp": "2026-09-21T07:32:10.123+0000",
  "agent":   { "name": "erp01" },
  "rule":    { "id": "100111", "level": 5, "groups": ["erpapp","local","authentication_failed"],
               "description": "erpapp: dang nhap that bai - user nvhung tu 192.168.10.24" },
  "data":    { "status": "FAILED", "dstuser": "nvhung", "srcip": "192.168.10.24",
               "url": "/api/login", "erp": { "reason": "bad_password" } }
}
```

Hai chi tiết quyết định cách viết rule YAML:

- Trường decoder gán **nằm dưới `data.`** → YAML viết `data.srcip`, `data.dstuser`,
  `data.erp.module`.
- `rule.id` là **chuỗi**, không phải số → YAML phải viết `["100130", "100131"]` có ngoặc
  kép. `_clause` cũng ép `str(v)` cho danh sách, đúng với kiểu này.

### Chặng 9 — Correlator quét

Cứ mỗi 60 giây (`POLL_INTERVAL`), với **từng** rule trong `correlation/rules/*.yml`:

```
end   = now
start = end − rule.window
POST https://wazuh.indexer:9200/wazuh-alerts-*/_search
```

Với dòng log đang truy vết, nó khớp filter của hai rule:

- `account_takeover_to_exfil`, giai đoạn `bi_do_mat_khau` (`rule.id: ["100111"]`,
  `min_count: 3`)
- gián tiếp qua 100120, giai đoạn `do_mat_khau` của `brute_force_then_success`

Nếu đủ điều kiện, engine sinh `Finding`. Chi tiết: Chương 3.

**Lưu ý về cửa sổ:** engine hỏi Indexer "trong 1 giờ qua có gì", không hỏi "có gì mới".
Nó **không có trạng thái**, không nhớ lần quét trước. Toàn bộ cơ chế chống trùng nằm ở
`doc_id` tất định ở chặng sau.

### Chặng 10 — Ghi alert tương quan

```
PUT https://wazuh.indexer:9200/siem-correlated-2026.09.21/_doc/<sha1(rule|key|bucket)>
```

Index riêng, template riêng (`sinks.py::INDEX_TEMPLATE`), tên theo ngày UTC.

Dashboard đọc **cả hai** index: `wazuh-alerts-*` cho alert thô, `siem-correlated-*` cho
alert tương quan. Hai lớp hiển thị tách bạch — đúng ý đồ "hai tầng rule"
(`docs/hai-tang-rule.md`).

## 0.3 Nhánh thứ hai — log firewall, và vì sao nó giá trị hơn

Cùng đường đi, khác ở chặng 5:

```
<13>Sep 21 14:33:02 fw01 kernel: [12345.678901] IPTABLES-DROP: IN=eth0 OUT= MAC=... SRC=203.0.113.77 DST=192.168.10.5 ... PROTO=TCP SPT=44321 DPT=3389 ... SYN URGP=0
```

| Chặng | Log ERP | Log firewall |
|---|---|---|
| decoder | `erpapp-*` — **tự viết** | decoder `kernel` — **có sẵn của Wazuh** |
| rule gốc | 100100 (tự viết) | 4100 (có sẵn) → 100200 (tự viết) |
| rule tần suất | 100120/100121 | 100220 (quét cổng) |

[Đã kiểm chứng — `scripts/simulate_attack.py`, hàm `ev_fw_drop`; rule 100200 có
`<if_sid>4100</if_sid>`]

**Vì sao nhánh này quan trọng hơn về mặt học thuật:** decoder không phải của bạn, log đúng
định dạng iptables thật. Nên khi rule tương quan `scan_then_login_attempt` nối được
`100220` (firewall) với `100111` (ứng dụng) qua `data.srcip`, nó chứng minh **engine nối
được hai nguồn log độc lập** — và một nửa chuỗi dùng ruleset của Wazuh.

Đây là bằng chứng mạnh nhất chống lại lời phê "kiểm chứng vòng tròn". Nhớ kỹ để dùng.

## 0.4 Nhánh thứ ba — agent (thiết kế xong, lab chưa dùng)

```
endpoint ──1515/tcp──► authd      (đăng ký lần đầu, use_password=no)
         ──1514/tcp──► remoted    (gửi sự kiện, đã mã hoá)
```

Agent gửi cả FIM (`syscheck`), SCA, syscollector, vulnerability-detection. Từ chặng 3 trở
đi giống hệt luồng syslog.

[Suy luận] Lab hiện không có agent thật gửi log, nên các rule ID SSH/Windows trong
`smb_attack_chain.yml` (5710, 5715, 40112, 60106...) chưa từng khớp trong thực tế — xem
Chương 7, mục 7.11.

Hệ quả cho phép đo hiệu năng: FIM realtime trên `/etc`, `/usr/bin`, `/boot` sẽ sinh **nhiều
log hơn hẳn** trên máy thật. Đây là lý do `measure_capacity.sh` tự cảnh báo rằng phép ngoại
suy có thể sai đáng kể.

## 0.5 Nhánh thứ tư — đường quay ngược (chưa bật)

```
correlator ──unix socket──► /var/ossec/queue/sockets/queue
                              │
                              ▼
                     decoder json có sẵn
                              │
                     100900 (level 0)
                       ├── 100901 severity=medium   → level 10
                       ├── 100902 severity=high     → level 12
                       └── 100903 severity=critical → level 14
```

Mục đích: cho alert tương quan đi qua ruleset để hưởng active response và email.

**Chưa chạy** — `MANAGER_SOCKET` không được đặt trong compose, socket chưa mount.
[Đã kiểm chứng — khối `correlator` trong `docker-compose.yml`]. Xem Chương 7, mục 7.6, và
cảnh báo vòng lặp ở mục 7.12 trước khi bật.

## 0.6 Độ trễ tích luỹ — trả lời câu "bao lâu thì biết"

| Chặng | Độ trễ | Ghi chú |
|---|---|---|
| sinh → remoted | mili giây | mạng LAN |
| remoted → analysisd | mili giây | trừ khi hàng đợi đầy |
| analysisd → `alerts.json` | tức thì | ghi đĩa |
| filebeat → Indexer | vài giây | [Suy luận] mặc định của filebeat, chưa đo trong repo |
| Indexer → truy vấn được | ~1 giây | `refresh_interval` mặc định của OpenSearch |
| correlator quét | **0–60 giây** | phụ thuộc rơi vào đâu trong chu kỳ |

**Lớp 1–2 (rule Wazuh): gần như tức thì.** Alert xuất hiện trong vài giây.

**Lớp 3 (tương quan): xấu nhất khoảng 60 giây + vài giây độ trễ đẩy.** Đây là câu trả lời
cho "MTTD của hệ thống là bao nhiêu" — kèm ghi chú rằng đó là hệ quả trực tiếp của lựa
chọn kiến trúc quét-theo-chu-kỳ.

Cẩn thận khi đo MTTD từ `@timestamp` của alert tương quan — xem Chương 7, mục 7.3.

## 0.7 Log chết ở đâu — bảng chẩn đoán theo chặng

Học bảng này thì gỡ lỗi demo không cần đoán. Kiểm tra theo thứ tự từ trên xuống.

| Chặng | Triệu chứng | Kiểm tra bằng |
|---|---|---|
| 1 sinh | không có gì xảy ra | `simulate_attack.py --print-only` xem nội dung dòng log |
| 2 nhận | gói bị bỏ vì ngoài `allowed-ips` | **không có log** — điểm mù; kiểm bằng `tcpdump` hoặc thử từ trong mạng Docker |
| 3 hàng đợi | sự kiện bị vứt | `ossec.log` trong container manager |
| 4–5 decode | log vào nhưng không thành trường | `wazuh-logtest` — `bash scripts/test_rules.sh` |
| 6 rule | decode đúng, rule không nổ | `wazuh-logtest` in rule nào khớp |
| 6 rule nổ nhầm | rule sai hướng | `bash scripts/negative_rule_test.sh` |
| 7 ghi đĩa | level < 3 nên không ghi | kiểm level của rule trong `local_rules.xml` |
| 8 filebeat | alert có trong `alerts.json` nhưng không lên Indexer | đếm `wazuh-alerts-*/_count`; đọc log container manager |
| 9 correlator | Indexer có alert, không có alert tương quan | `docker compose logs correlator` tìm dòng `Vong quet xong` |
| 10 ghi | correlator báo có finding nhưng index rỗng | `python -m siem_correlator --dry-run --once` |
| hiển thị | index có dữ liệu, dashboard trống | index pattern `siem-correlated-*` chưa được tạo trong Dashboard |

**Nguyên tắc chẩn đoán:** luôn đi từ chặng 1 xuống, và luôn kiểm tra `wazuh-alerts-*`
**trước** `siem-correlated-*`. Không có alert thô thì engine không có gì để tương quan —
đi tìm lỗi trong engine lúc đó là tìm nhầm chỗ.

## 0.8 Tự kiểm tra — Chương 0

1. Vẽ lại bản đồ ở mục 0.1 trên giấy, kèm số cổng, trong 2 phút.
2. Correlator nằm ở đâu trên đường đi của log? Nó chết thì mất gì?
3. Một dòng log ERP đi qua bao nhiêu tiến trình trước khi thành alert trên Indexer? Kể tên.
4. `<13>` trong gói syslog là gì? Phần nào của dòng log thành `program_name`?
5. Vì sao decoder cha không cần regex cho `Sep 21 14:32:10 erp01`?
6. `logall no` nghĩa là gì và đánh đổi là gì?
7. Alert nằm ở file nào trong container manager trước khi lên Indexer?
8. Vì sao rule YAML phải viết `data.srcip` chứ không phải `srcip`?
9. Engine có nhớ lần quét trước không? Vậy chống trùng bằng cách nào?
10. Dashboard tương quan trống — kiểm tra theo thứ tự nào, và **chỗ đầu tiên** phải nhìn là gì?

**Bài tập (60 phút) — đi hết luồng bằng tay.** Chạy một sự kiện duy nhất, rồi bám theo nó
qua từng chặng: `--print-only` xem dòng log → `wazuh-logtest` xem decode và rule →
đếm `wazuh-alerts-*/_count` trước và sau → `--dry-run --once` xem finding. Làm một lần là
nhớ cả đời.
# CHƯƠNG 1 — Decoder Wazuh

## 1.1 Nguyên lý

Wazuh nhận log là **một dòng chữ**. Dòng chữ không tra cứu được, không đếm được,
không so sánh được. Decoder làm một việc duy nhất: **cắt dòng chữ thành các trường
có tên**.

```
Aug 25 13:41:55 erp01 erpapp: EXPORT rows=25000 module=customer user=nvhung srcip=192.168.10.24 file=khachhang.csv
```

thành

```
erp.rows   = 25000
erp.module = customer
dstuser    = nvhung
srcip      = 192.168.10.24
erp.file   = khachhang.csv
```

Không có bước này thì rule không viết được, tương quan không làm được, dashboard không
vẽ được. **Decoder là móng của cả hệ thống.**

Thứ tự xử lý trong `wazuh-analysisd`:

```
log → decoder tiền xử lý (tách timestamp, hostname, program_name)
    → decoder cha khớp program_name
    → decoder con khớp prematch
    → regex bóc trường theo <order>
    → rule chạy trên các trường đã bóc
```

## 1.2 Trong repo này

File: `custom/decoders/local_decoder.xml`

### Decoder cha

```xml
<decoder name="erpapp">
  <program_name>^erpapp$</program_name>
</decoder>
```

Wazuh đã tách sẵn `program_name` từ định dạng syslog (`<13>Aug 25 13:41:55 erp01 erpapp: ...`
→ program_name = `erpapp`). Decoder cha chỉ làm cổng vào: dòng nào không phải của `erpapp`
thì không xét tiếp. Neo `^...$` để `erpappv2` không lọt vào.

### Decoder con

```xml
<decoder name="erpapp-export">
  <parent>erpapp</parent>
  <prematch offset="after_parent">^EXPORT </prematch>
  <regex offset="after_parent">^EXPORT rows=(\d+) module=(\w+) user=(\S+) srcip=(\S+) file=(\S+)</regex>
  <order>erp.rows, erp.module, dstuser, srcip, erp.file</order>
</decoder>
```

Bốn thẻ, bốn việc khác nhau:

| Thẻ | Việc |
|---|---|
| `<parent>` | chỉ xét khi decoder cha đã khớp |
| `<prematch>` | lọc nhanh — không khớp thì bỏ qua, khỏi chạy regex đắt |
| `<regex>` | bóc trường, mỗi `()` là một nhóm bắt |
| `<order>` | đặt tên cho các nhóm bắt, **khớp theo vị trí** |

`offset="after_parent"` nghĩa là regex chỉ xét **phần còn lại** sau khi decoder cha đã ăn.
Không có nó thì phải viết regex khớp cả `Aug 25 13:41:55 erp01 erpapp: EXPORT ...`.

**5 nhóm `()` ↔ 5 tên trong `<order>`.** Lệch một cái là gán sai trường và không có
thông báo lỗi nào — hệ thống chạy im ru với dữ liệu sai. Đây là loại lỗi nguy hiểm nhất
vì nó không kêu.

### Trường tĩnh và trường động — câu hỏi ăn điểm

Wazuh chia trường thành hai loại, và đây là chỗ hầu hết người mới vấp.

**Trường tĩnh (static)** — tập cố định do Wazuh định nghĩa sẵn: `srcip`, `dstuser`,
`srcuser`, `url`, `status`, `id`, `action`, `data`, `extra_data`...

- Trong rule gọi bằng **thẻ riêng**: `<srcip>`, `<status>`
- **KHÔNG** dùng được `<field name="srcip">` → `wazuh-analysisd` từ chối nạp ruleset và
  **chết hẳn** với `"ERROR: Failure to read rule 100101. Field 'srcip' is static"`
  [Đã kiểm chứng — comment rule 100101, `custom/rules/local_rules.xml`]

**Trường động (dynamic)** — mọi tên khác do mình đặt.

- Trong rule gọi bằng `<field name="ten">`, so sánh được bằng biểu thức
- Trên Indexer nằm ở `data.<tên>`

### Vì sao tiền tố `erp.`

Đây là câu "tại sao" tầng 2 — phải trả lời được.

Ba lý do, xếp theo mức quan trọng:

1. **Tránh đụng tên trường tĩnh.** Đặt `rows` hay `action` trần thì rơi vào vùng tên
   Wazuh đã giữ chỗ.
2. **Để thành trường động**, gọi được bằng `<field name="erp.rows">` với biểu thức —
   thứ mà trường tĩnh không cho.
3. **Để rule tương quan trỏ tới được.** Trên Indexer chúng nằm ở `data.erp.*`, nên
   YAML viết `data.erp.module` là chạm được.

Quan sát thêm trong `<order>` của `erpapp-export`: `dstuser` và `srcip` **không** có
tiền tố vì đó là trường tĩnh chuẩn của Wazuh — dùng đúng tên chuẩn thì dashboard có sẵn
của Wazuh tự hiểu, và rule tương quan join được bằng `data.srcip` chung cho mọi nguồn log.
**Đây chính là thứ cho phép nối log firewall với log ứng dụng.**

### Một chi tiết tinh tế: `dstuser` hay `srcuser`?

| Decoder | Trường người dùng | Vì sao |
|---|---|---|
| `erpapp-auth` | `dstuser` | người **bị** đăng nhập vào — đích của hành động |
| `erpapp-export` | `dstuser` | người thực hiện, nhưng gán `dstuser` để join với chuỗi đăng nhập |
| `erpapp-perm` | `dstuser` = người được cấp quyền, `srcuser` = người cấp | hai vai khác nhau, phải tách |
| `erpapp-txn` | `srcuser` | người thực hiện giao dịch — nguồn của hành động |

[Đã kiểm chứng — `custom/decoders/local_decoder.xml`, các thẻ `<order>`]

Hệ quả thiết kế: rule tương quan `account_takeover_to_exfil` join theo `data.dstuser`
nối được chặng "đăng nhập" với chặng "xuất dữ liệu" **chỉ vì** cả hai decoder đều gán
người dùng vào `dstuser`. Nếu `erpapp-export` gán `srcuser` thì chuỗi đứt.

**Nếu bị hỏi "sao xuất dữ liệu lại là dstuser, người đó là chủ thể mà?":** trả lời thẳng —
về mặt ngữ nghĩa `srcuser` đúng hơn, nhưng chọn `dstuser` để giữ một khoá join xuyên suốt
chuỗi tấn công. Đó là đánh đổi có chủ đích giữa ngữ nghĩa và khả năng tương quan.

## 1.3 Tự kiểm tra — Chương 1

1. Giải thích `offset="after_parent"` mà không nhìn tài liệu.
2. `<prematch>` và `<regex>` khác nhau chỗ nào? Bỏ `<prematch>` thì sao?
3. Vì sao `erp.rows` có tiền tố mà `srcip` thì không?
4. Wazuh báo `"Field 'extra_data' is static"` — nguyên nhân và cách sửa?
5. Trong `erpapp-perm`, `dstuser` và `srcuser` ai cấp quyền cho ai?

**Bài tập tay (60 phút).** Đổi `erp.rows` thành `extra_data` trong decoder, nạp lại
ruleset, xem manager chết ra sao, rồi sửa lại:

```bash
bash scripts/test_rules.sh
```

---

# CHƯƠNG 2 — Rule Wazuh (lớp phát hiện 1 và 2)

## 2.1 Nguyên lý

Rule Wazuh trả lời câu hỏi: *sự kiện vừa decode có đáng báo động không?*

Ba cơ chế, độ phức tạp tăng dần:

1. **Rule không trạng thái** — xét một sự kiện đơn lẻ. "Đăng nhập thất bại" → level 5.
2. **Rule tần suất** — `frequency` + `timeframe`, đếm nhiều sự kiện trong cửa sổ.
   "6 lần thất bại trong 120 giây" → brute force.
3. **Rule phụ thuộc** — `if_sid` / `if_matched_sid`, chỉ xét khi rule khác đã khớp.

### Thang level 0–15

| Level | Ý nghĩa | Trong repo |
|---|---|---|
| 0 | không ghi alert, chỉ để rule khác tham chiếu | 100100, 100900 |
| 1–2 | dưới ngưỡng ghi alert, nhưng **được đếm tần suất** | 100101–100106, 100200 |
| 3–5 | sự kiện bình thường có ghi nhận | 100110, 100111, 100130 |
| 6–9 | đáng chú ý | 100122, 100140, 100150 |
| 10–12 | tấn công | 100120, 100121, 100131, 100141 |
| 13–15 | nghiêm trọng | 100903 |

`ossec.conf` đặt `<log_alert_level>3</log_alert_level>` → chỉ level ≥ 3 mới được ghi
thành alert và đẩy lên Indexer. **Đây là lý do level 1 và 2 tồn tại**: đủ thấp để không
sinh nhiễu, nhưng vẫn nằm trong danh sách đối chiếu tần suất.

### Ba cơ chế gom nhóm — phải phân biệt được

| Thẻ | Nghĩa | Dùng cho |
|---|---|---|
| `<same_source_ip />` | các sự kiện phải cùng một IP nguồn | mọi rule tần suất theo IP |
| `<same_user />` | phải cùng một tài khoản | brute force |
| `<different_field>dstuser</different_field>` | phải **khác** tài khoản | password spraying |

Khác biệt giữa hai dòng cuối chính là khác biệt giữa hai kiểu tấn công:

- **Brute force** = một mật khẩu sai nhiều lần trên **cùng** một tài khoản
- **Password spraying** = một mật khẩu phổ biến thử trên **nhiều** tài khoản khác nhau

## 2.2 Trong repo này — những quyết định phải giải thích được

File: `custom/rules/local_rules.xml`. Repo đặt dải ID `100000–100999` cho rule local
theo quy ước Wazuh.

Sáu quyết định dưới đây đều xuất phát từ lỗi đã vấp thật. **Kể lại chúng trước hội đồng
là điểm cộng lớn** — nó chứng minh bạn tự viết, tự vấp, tự sửa.

### (1) Vì sao phải neo dấu mũ và dollar cho OK

```xml
<rule id="100110" level="3">
  <if_sid>100100</if_sid>
  <status>^OK$</status>
  ...
```

Không neo thì `<status>OK</status>` là **so khớp chuỗi con**. Hệ quả dây chuyền:

```
result=NOTOK         → khớp "OK" → bị xếp vào ĐĂNG NHẬP THÀNH CÔNG
result=TOKEN_EXPIRED → tương tự
result=BLOCKED       → tương tự
```

Rule tương quan `brute_force_then_success` lấy 100110 làm chặng "đăng nhập thành công".
Kết quả: **một cuộc tấn công bị khoá tài khoản lại được báo là đã chiếm được tài khoản.**
Kết luận ngược hoàn toàn.

[Đã kiểm chứng — comment rule 100110, `custom/rules/local_rules.xml`; ca hồi quy trong
`scripts/negative_rule_test.sh`]

**Nguyên tắc rút ra, phát biểu được thành câu:** mọi phép so khớp trên trường trạng thái
đều phải neo hai đầu. Không neo là so khớp chuỗi con.

### (2) Vì sao 100200 là level 2 chứ không phải level 0

```xml
<rule id="100200" level="2">
  <if_sid>4100</if_sid>
  <description>Su kien firewall</description>
</rule>
```

Trực giác nói: rule mồi thì để level 0 cho khỏi sinh nhiễu. Nhưng `analysisd` **không lưu
sự kiện của rule level 0 vào danh sách đối chiếu tần suất**. Để level 0 thì
100220 (`<if_matched_sid>100200</if_matched_sid>`, `frequency=15`) **không bao giờ nổ**.

Level 2 giải quyết cả hai: đủ cao để được đếm, đủ thấp để dưới `log_alert_level=3` nên
không ghi alert.

[Đã kiểm chứng — comment rule 100200]

### (3) Vì sao cần type pcre2 cho 100131

```xml
<field name="erp.rows" type="pcre2">^[1-9][0-9]{4,}$</field>
```

Hai lỗi lồng nhau ở đây:

**Lỗi thứ nhất — regex sai logic.** Bản cũ đếm số chữ số bằng chuỗi `\d` lặp lại, nên
`rows=00012` (12 dòng, ứng dụng đệm số 0) vẫn khớp → báo "xuất dữ liệu hàng loạt" mức 10
cho một thao tác xuất 12 dòng.

**Lỗi thứ hai — dùng đúng regex nhưng sai engine.** `os_regex` mặc định của OSSEC
**không hỗ trợ lớp ký tự `[1-9]`**. Viết lớp ký tự bằng `os_regex` thì rule
**không báo lỗi khi nạp** nhưng **không bao giờ khớp** → `rows=25000` tụt xuống 100130,
mất hẳn cảnh báo mức 10.

Lỗi thứ hai độc hơn lỗi thứ nhất: nó im lặng. Phải khai báo `type="pcre2"` mới có
lớp ký tự.

[Đã kiểm chứng — comment rule 100131, kèm bảng kiểm chứng bằng `wazuh-logtest`]

### (4) Vì sao khung giờ ghi `10:30 - 00:30` lại là "ngoài giờ hành chính"

Ý định: giờ làm việc T2–T6 07:30–17:00 **giờ Việt Nam**, cộng 30 phút ra về → cảnh báo
đăng nhập trước 07:30 hoặc từ 17:30 các ngày T2–T6, và cả ngày T7, CN.

Thẻ `<time>` và `<weekday>` đối chiếu theo **UTC**, không đọc timestamp trong log, không
theo múi giờ container. Đã thử cả `TZ=Asia/Ho_Chi_Minh` lẫn ghi đè `/etc/localtime`:
`ossec.log` chuyển sang +07 nhưng `<time>` vẫn so theo UTC.

```
07:30 VN − 7 = 00:30 UTC
17:30 VN − 7 = 10:30 UTC
```

Khung "trong giờ" 00:30–10:30 UTC nằm gọn trong **một ngày UTC**, nên thứ UTC trùng thứ VN
suốt giờ làm → chỉ cần 2 rule:

| Rule | Điều kiện UTC | Tương ứng giờ VN |
|---|---|---|
| 100122 | `weekdays` + `10:30 - 00:30` | T2–T6 17:30 → 07:30 hôm sau (kể cả T7 00:00–07:00) |
| 100123 | `weekends` | T7 07:00 → T2 07:00 |

Nếu giờ vào làm sớm hơn 07:00 VN, khung vắt qua nửa đêm UTC → thứ UTC lệch thứ VN → phải
tách rule theo ngày.

Trước khi trừ 7 tiếng, khung `10 pm - 5 am` bắt đúng **09:00–12:00 giờ VN** — giờ làm việc
cao điểm — và sinh **469 cảnh báo sai**.

[Đã kiểm chứng — cơ sở UTC của `<time>`: comment rule 100122, hai ca probe bằng sự kiện thật]
[Đã kiểm chứng 2026-09-28 — 5 probe syslog trên stack: khung vắt nửa đêm + `weekdays` nổ đúng,
`<weekday>` lọc theo thứ UTC; bảng trong comment rule 100122. Độ phủ cả tuần kiểm bằng mô phỏng
từng phút. Chưa kiểm: mốc cuối `<time>` tính bao gồm hay loại trừ]

Con số 469 là một trong những con số có giá trị nhất trong đồ án: nó là **bằng chứng
định lượng của một false positive thật**, do chính bạn phát hiện và sửa. Đưa vào
chương 5 của báo cáo.

### (5) Chuỗi 100101–100106 — chống "mù im lặng"

Đây là phần thiết kế tinh vi nhất trong file rule, và cũng khó giải thích nhất. Đọc kỹ.

**Vấn đề:** ứng dụng đổi định dạng log → regex decoder trượt → dòng log rơi về 100100
(level 0) → không ghi alert → **không ai biết hệ thống đã mù**. Giám sát chết mà bảng
điều khiển vẫn xanh.

**Giải pháp ngây thơ và vì sao nó hỏng:** viết một rule "bắt dòng AUTH/EXPORT/PERM/TXN
mà không decode được". Nhưng Wazuh **không có phép thử trường vắng mặt** —
`<field name="erp.module" negate="yes">` **không khớp** khi trường không tồn tại.
[Đã kiểm chứng — comment rule 100101, đo bằng `wazuh-logtest` trên Wazuh 4.9.2]

**Giải pháp thật — đảo ngược logic, chỉ dùng phép thử trường CÓ MẶT:**

```
100103–100106 (level 2): "AUTH/EXPORT/PERM/TXN đã decode tốt"  ← thử trước
100101        (level 1): "dòng không decode được"              ← thử sau cùng
100102        (level 7): 5 dòng hỏng / 300 giây → báo động
```

Cơ chế dựa trên một tính chất của `analysisd`: **rule anh em được thử theo level giảm dần**,
không theo thứ tự trong file. Một dòng chỉ rơi xuống 100101 (level 1) khi đã trượt hết
mọi rule nghiệp vụ (level 3–12) **và** trượt cả bốn rule level 2 — tức thật sự không bóc
được trường nào.

**Vì sao chỉ đặt level thấp thôi là chưa đủ** (bản đầu tiên chỉ có `<match>`, không kiểm
trường): "được thử sau cùng" không đồng nghĩa "chỉ khớp khi decode hỏng". Một dòng
`EXPORT module=product` decode **hoàn hảo** nhưng không rule nghiệp vụ nào nhận
(100130 chỉ nhận `^customer$|^employee$|^payroll$`) → rơi xuống 100101 → bị đếm là
"decoder hỏng". Hậu quả đo được: chạy `benign_traffic.py` một phút đã đủ 5 dòng/300s
để 100102 (level 7) nổ **trên lưu lượng hoàn toàn lành tính** → FP giả tạo, làm sai
luôn Precision và F1.

[Đã kiểm chứng — comment rule 100101]

**Nếu chỉ nhớ được một ví dụ từ cả file rule, hãy nhớ ví dụ này.** Nó cho thấy bạn hiểu
cả cơ chế nội tại của `analysisd` lẫn ảnh hưởng của một lỗi rule lên số liệu đánh giá.

### (6) Vì sao 100120 cần same_user

100120 (brute force) và 100121 (spraying) **cùng nghe** rule 100111. `analysisd` dừng ở
rule đầu tiên khớp → không có `<same_user />` thì 100120 ăn hết sự kiện và 100121
**không bao giờ nổ**.

[Đã kiểm chứng — comment rule 100120]

Đây là ví dụ tốt để trả lời câu "hai rule chồng nhau thì sao": trong Wazuh, rule anh em
cạnh tranh nhau, phải tách ngưỡng rõ ràng.

### Nhóm 100900–100903 — đường quay ngược

```xml
<rule id="100900" level="0">
  <decoded_as>json</decoded_as>
  <field name="correlation_rule">\.+</field>
</rule>
```

Nhóm này tiếp nhận alert do correlator Python bắn **ngược** vào manager qua socket, để
alert tương quan cũng đi qua ruleset và hưởng được active response / email. Ánh xạ
`severity` → level: `medium`→10, `high`→12, `critical`→14.

**Quan trọng:** đường này **hiện không chạy** vì `MANAGER_SOCKET` chưa được đặt và socket
chưa được mount vào container correlator. [Đã kiểm chứng — `docker/single-node/docker-compose.yml`
khối `correlator` không có biến `MANAGER_SOCKET`]. Xem Chương 7, mục 7.6.

Nếu hội đồng hỏi về active response cho alert tương quan: trả lời thẳng là đã thiết kế
xong đường đi (sink + 4 rule) nhưng chưa kích hoạt và chưa kiểm chứng. Đừng nói là "có".

## 2.3 Tự kiểm tra — Chương 2

1. Vì sao 100100 để level 0 được mà 100200 thì không?
2. Brute force và password spraying khác nhau ở **thẻ nào** trong rule?
3. `if_sid` và `if_matched_sid` khác nhau chỗ nào?
4. Vì sao `os_regex` không dùng được `[1-9]`, và hậu quả im lặng của nó là gì?
5. Kể lại cơ chế 100101–100106 trong 90 giây, không nhìn file.
6. Muốn đổi khung giờ cảnh báo thành 20:00–06:00 giờ VN thì ghi gì vào `<time>`?

**Bài tập (45 phút).** Đọc `scripts/negative_rule_test.sh`, hiểu `MUST` khác `MUST_NOT`
chỗ nào, và vì sao `test_rules.sh` (đối chiếu bằng mắt) không bắt được lỗi "rule nổ nhầm":

```bash
bash scripts/negative_rule_test.sh
```

---

# CHƯƠNG 3 — Engine tương quan (lớp phát hiện 3, phần tự viết nhiều nhất)

645 dòng Python, 7 file. Đây là phần hội đồng khoan sâu nhất vì nó không phải sản phẩm
có sẵn. Chương này dài nhất, đọc chậm.

## 3.1 Vì sao cần lớp thứ ba — trả lời trước khi bị hỏi

Câu hỏi gần như chắc chắn xuất hiện: *"Wazuh đã có rule tần suất rồi, viết thêm engine
làm gì?"*

Ba giới hạn của rule Wazuh mà engine lấp:

| Giới hạn của Wazuh | Engine làm được |
|---|---|
| `frequency`/`timeframe` chỉ đếm sự kiện **cùng loại** | nối nhiều **loại** sự kiện khác nhau thành chuỗi |
| Không nối được sự kiện từ **nguồn log khác nhau** | join firewall + ứng dụng qua `data.srcip` |
| Cửa sổ tối đa ngắn, trạng thái giữ trong RAM của `analysisd` | cửa sổ tới 2 giờ, truy vấn thẳng trên dữ liệu đã lưu |

Ví dụ cụ thể nhất — `account_takeover_to_exfil`: dò mật khẩu (100111) → đăng nhập thành
công (100110) → xuất dữ liệu (100130/100131). Ba **loại** sự kiện khác nhau, trải trong
1 giờ, join theo `data.dstuser`. Không rule Wazuh đơn lẻ nào diễn đạt được chuỗi này.

Tài liệu `docs/hai-tang-rule.md` (233 dòng) bàn sâu câu này — đọc trước khi bảo vệ.

## 3.2 Luồng chạy — vẽ được trên giấy trong 2 phút

```
__main__.py:  vòng lặp, mỗi POLL_INTERVAL (60s)
  │
  ├── load_rules()      rules.py    — đọc YAML → dataclass CorrelationRule, validate
  │
  └── với mỗi rule:
        engine.run()    engine.py
          │  end   = now
          │  start = end − rule.window
          │
          ├── build_filter()  dịch dict YAML → mệnh đề query OpenSearch
          ├── client.search() indexer.py — POST /wazuh-alerts-*/_search
          ├── đọc bucket, so ngưỡng → sinh Finding
          │
          └── sink.emit()     sinks.py
                ├── IndexerSink  → PUT /siem-correlated-YYYY.MM.DD/_doc/<doc_id>
                └── ManagerSink  → unix socket (hiện chưa bật)
```

Ba con số phải nhớ: `POLL_INTERVAL = 60` giây, `MAX_BUCKETS = 500`, `terms size = 50`
trong `_run_distinct`.

## 3.3 Từ YAML đến query — hàm `_clause`

Đây là trái tim của việc "dịch rule thành truy vấn". 8 dòng, phải đọc hiểu từng nhánh.

```python
def _clause(field_name: str, value: Any) -> dict[str, Any]:
    for suffix, op in (("__gte","gte"), ("__lte","lte"), ("__gt","gt"), ("__lt","lt")):
        if field_name.endswith(suffix):
            return {"range": {field_name[: -len(suffix)]: {op: value}}}
    if isinstance(value, list):
        return {"terms": {field_name: [str(v) for v in value]}}
    if isinstance(value, str) and ("*" in value or "?" in value):
        return {"wildcard": {field_name: value}}
    return {"term": {field_name: value}}
```

Bốn nhánh, xét theo thứ tự:

| YAML | Query sinh ra | Nghĩa |
|---|---|---|
| `rule.level__gte: 10` | `{"range": {"rule.level": {"gte": 10}}}` | so sánh lớn hơn/nhỏ hơn |
| `rule.id: ["100130","100131"]` | `{"terms": {...}}` | khớp một trong danh sách |
| `agent.name: "web-*"` | `{"wildcard": {...}}` | khớp mẫu |
| `rule.groups: "syscheck"` | `{"term": {...}}` | khớp chính xác |

**Hậu tố `__gte` là quy ước tự đặt**, không phải cú pháp OpenSearch. Nó cho phép viết
rule YAML phẳng, không lồng nhau. Đây là một quyết định thiết kế — giải thích được thì
chứng minh bạn hiểu code mình viết.

Mọi mệnh đề đều nằm trong `filter` (không phải `must`) → **không tính điểm liên quan**,
chỉ lọc. Nhanh hơn và cache được. [Suy luận — dựa trên cách OpenSearch xử lý filter
context; chưa đo benchmark trong repo này]

## 3.4 Ba kiểu rule

### `threshold` — đếm SỐ LƯỢNG

Câu hỏi nó trả lời: *khoá nào có từ N sự kiện trở lên trong cửa sổ?*

```python
"aggs": {"keys": {"terms": {"field": rule.group_by,
                            "size": MAX_BUCKETS,
                            "min_doc_count": rule.min_count},
                  "aggs": {"sample": {"top_hits": {"size": 3, ...}}}}}
```

`min_doc_count` đẩy phép lọc ngưỡng **xuống Indexer** — bucket dưới ngưỡng không được
trả về, tiết kiệm băng thông. `top_hits size 3` lấy 3 alert mẫu làm **chứng cứ** đính
kèm finding, để người trực mở ra biết chuyện gì xảy ra chứ không chỉ thấy con số.

Ví dụ: `mass_data_export_by_user` — `group_by: data.dstuser`, `min_count: 5`,
`window: 1800`.

### `distinct` — đếm SỐ GIÁ TRỊ KHÁC NHAU

Câu hỏi: *khoá nào chạm tới từ N giá trị khác nhau trở lên?*

```python
"aggs": {"keys": {"terms": {"field": rule.group_by, "size": MAX_BUCKETS},
                  "aggs": {"values": {"terms": {"field": rule.distinct_field,
                                                "size": 50}}}}}
...
if len(values) < rule.min_cardinality:
    continue
```

Ví dụ: `impossible_travel` — `group_by: data.dstuser`, `distinct_field: data.srcip`,
`min_cardinality: 3`, `window: 900`.

**Câu hỏi bẫy hay gặp: threshold khác distinct chỗ nào?**
Threshold đếm **lần**, distinct đếm **loại**. Một tài khoản đăng nhập 100 lần từ **một**
IP: threshold nổ, distinct không. Đó chính là ranh giới giữa brute force và spraying,
và giữa "dùng nhiều" với "dùng từ nhiều nơi".

**Điểm yếu phải tự nêu:** `size: 50` ở tầng trong. Nếu một khoá có hơn 50 giá trị khác
nhau, `len(values)` bị chặn ở 50. Với `min_cardinality: 3` thì không ảnh hưởng (3 < 50),
nhưng một rule tương lai đặt `min_cardinality > 50` sẽ **không bao giờ nổ**.
[Suy luận — đọc từ `_run_distinct`, chưa dựng thực nghiệm]. Cách đúng là dùng
aggregation `cardinality` thay cho `terms`; đánh đổi là mất danh sách giá trị làm chứng cứ.

### `sequence` — nhiều giai đoạn ĐÚNG THỨ TỰ

Phức tạp nhất, và là chỗ chứa điểm yếu lớn nhất.

Cơ chế 3 bước:

**Bước 1** — với mỗi giai đoạn, chạy một query riêng, gom theo `join_field`, lấy mốc
thời gian đầu và cuối:

```python
"aggs": {"keys": {"terms": {"field": rule.join_field, ...},
                  "aggs": {"first_seen": {"min": {"field": "@timestamp"}},
                           "last_seen":  {"max": {"field": "@timestamp"}}}}}
```

**Bước 2** — giao tập hợp khoá: khoá phải xuất hiện ở **mọi** giai đoạn.

```python
common = set(per_stage[0])
for buckets in per_stage[1:]:
    common &= set(buckets)
```

**Bước 3** — kiểm tra thứ tự thời gian:

```python
ordered = all(timeline[i]["first"] <= timeline[i+1]["last"]
              for i in range(len(timeline)-1))
```

### Điểm yếu của điều kiện thứ tự — PHẢI TỰ NÊU TRƯỚC

Điều kiện so `first` của giai đoạn trước với `last` của giai đoạn sau. Đây là điều kiện
**lỏng**: nó chỉ đòi giai đoạn sau **kết thúc** sau khi giai đoạn trước **bắt đầu**, chứ
không đòi giai đoạn sau **bắt đầu** sau.

Ví dụ dương tính giả cụ thể (`docs/bao-ve-hoi-dong.md` Câu 1) — rule
`account_takeover_to_exfil`, join theo `data.dstuser`, cửa sổ 1 giờ. Một kế toán viên
trong buổi sáng bình thường:

| Thời điểm | Sự kiện | Rơi vào giai đoạn |
|---|---|---|
| 09:05 | đăng nhập đầu ngày (100110) | stage2 |
| 09:10 | xuất báo cáo công nợ (100130) | stage3 |
| 09:20 | xuất báo cáo bán hàng (100130) | stage3 |
| 09:30–09:32 | hết phiên, gõ sai mật khẩu 3 lần (100111 ×3) | stage1 |
| 09:50 | đăng nhập lại thành công (100110) | stage2 |

Giá trị tổng hợp: `stage1.first = 09:30`; `stage2.first = 09:05, last = 09:50`;
`stage3.first = 09:10, last = 09:20`.

- `stage1.first (09:30) <= stage2.last (09:50)` → đúng
- `stage2.first (09:05) <= stage3.last (09:20)` → đúng

→ **Rule nổ, severity `critical`**, kết luận "tài khoản bị chiếm rồi xuất dữ liệu".
Thực tế: không có tấn công nào.

**Học thuộc ví dụ này.** Tự nêu kèm số liệu cụ thể = chủ động, chứng tỏ hiểu code mình
viết. Bị moi ra = bị động, mất điểm nặng.

**Cách sửa** (`docs/adr/0001-kien-truc-tong-the.md` mục 6, khoảng trống #2): siết thành
`first[i] <= first[i+1]`. Chặt hơn nhưng vẫn không hoàn hảo — vì so trên giá trị tổng hợp
của cả bucket chứ không so từng sự kiện. Muốn chặt tuyệt đối phải kéo từng sự kiện về rồi
duyệt, đắt hơn nhiều bậc.

**Đây là đánh đổi có chủ đích, và phải trình bày như vậy:** một query tổng hợp cho mỗi
giai đoạn, độ phức tạp theo số giai đoạn chứ không theo số sự kiện. Đổi lại là độ chính
xác thứ tự. Với quy mô SME thì đánh đổi này hợp lý; nói được câu này là khác hẳn với
"em không biết nó lỏng".

## 3.5 `doc_id` tất định — chi tiết tinh tế nhất

```python
@property
def doc_id(self) -> str:
    bucket = int(self.window_end.timestamp()) // max(self.rule.window, 1)
    raw = f"{self.rule.id}|{self.key}|{bucket}"
    return hashlib.sha1(raw.encode()).hexdigest()
```

**Vấn đề nó giải quyết:** vòng quét chạy mỗi 60 giây, nhưng cửa sổ rule có thể là 3600
giây. Cùng một chuỗi tấn công bị quét lại **60 lần** trước khi trôi ra khỏi cửa sổ. Không
xử lý thì sinh 60 alert trùng cho một sự việc → dashboard ngập, người trực bỏ đọc.

**Cách giải:** băm bộ ba `(rule_id, khoá, số hiệu ô thời gian)` thành `_id`. Ghi bằng
`PUT /_doc/<id>` → OpenSearch **ghi đè** thay vì thêm mới. 60 lần quét → 1 document.

Phép chia nguyên `// rule.window` chia trục thời gian thành các **ô cố định** độ dài bằng
cửa sổ rule. Mọi lần quét rơi vào cùng một ô cho ra cùng `_id`.

**Hệ quả phải nói được:** một chuỗi tấn công nằm vắt qua ranh giới hai ô vẫn sinh **2**
alert. Đó là giá phải trả cho cách chia ô cố định, không phải lỗi.

**Lợi ích phụ:** correlator trở nên *idempotent* — chạy `--once` bao nhiêu lần cũng không
sinh bản trùng. Rất tiện khi demo trước hội đồng.

**Điểm yếu chưa xử lý** (xem Chương 7, mục 7.3): vì là ghi đè toàn bộ document, trường
`@timestamp` cũng bị ghi đè bằng `window_end` mới mỗi vòng quét. Điều này ảnh hưởng tới
phép đo MTTD.

## 3.6 Các file còn lại — đọc lướt nhưng phải biết có gì

### `rules.py` — nạp và kiểm tra rule

`CorrelationRule` là dataclass; `validate()` bắt lỗi cấu hình **khi khởi động** chứ không
để chết giữa chừng:

- `type` phải thuộc `{threshold, distinct, sequence}`
- `threshold`/`distinct` bắt buộc có `group_by`
- `distinct` bắt buộc có `distinct_field`
- `sequence` bắt buộc có `join_field` và ít nhất 2 stage
- `window` phải > 0

`load_rules()` bỏ qua file YAML lỗi và ghi log (một file hỏng không làm chết cả engine),
nhưng **trùng `id` thì ném `ValueError`** làm dừng hẳn. Lựa chọn có lý: file hỏng là sự cố
cục bộ, trùng id là lỗi logic khiến alert bị ghi đè lẫn nhau qua `doc_id`.

### `indexer.py` — client HTTP mỏng

Chỉ `requests`, không dùng thư viện opensearch-py. Bốn phương thức: `ping`, `search`,
`index_doc`, `ensure_index_template`. **Lý do chọn mỏng:** ít phụ thuộc, dựng lại ở đâu
cũng được, và đọc được hết trong 5 phút — quan trọng khi phải giải thích trước hội đồng.

`search()` truyền `ignore_unavailable=true` và `allow_no_indices=true` → index chưa tồn
tại thì trả rỗng thay vì lỗi. Cần thiết vì `siem-correlated-*` chưa có gì lúc chạy lần đầu.

### `sinks.py` — hai đường ra

`IndexerSink` ghi thẳng vào `siem-correlated-YYYY.MM.DD`, có `INDEX_TEMPLATE` khai báo
kiểu dữ liệu từng trường. Chú ý `"evidence": {"type": "object", "enabled": False}` —
lưu nhưng **không lập chỉ mục**, vì chứng cứ chỉ để người đọc, không để truy vấn. Tiết
kiệm dung lượng và tránh bùng nổ số trường.

`ManagerSink` bắn JSON vào unix datagram socket của manager với định dạng
`<queue>:<location>:<payload>`. **Hiện chưa hoạt động** — xem Chương 7, mục 7.6.

### `config.py` — cấu hình qua biến môi trường

12 thiết lập, tất cả có mặc định. `frozen=True` → không sửa được lúc chạy.
**Lưu ý:** `lookback_slack` được khai báo và đọc từ môi trường nhưng **không nơi nào dùng**
— xem Chương 7, mục 7.13.

## 3.7 Tự kiểm tra — Chương 3

1. Vẽ luồng từ vòng lặp `__main__` tới lúc alert nằm trong Indexer, trên giấy, 2 phút.
2. `threshold` và `distinct` khác nhau thế nào? Cho ví dụ dữ liệu mà một cái nổ, cái kia không.
3. Giải thích `doc_id`: nó giải quyết vấn đề gì, và nó **không** giải quyết được vấn đề gì?
4. Vì sao `_run_sequence` phải chạy nhiều query chứ không một query?
5. Nêu ví dụ dương tính giả của điều kiện thứ tự, kèm mốc thời gian cụ thể.
6. `MAX_BUCKETS = 500` — chuyện gì xảy ra khi vượt? Hệ thống có báo không?
7. Vì sao `evidence` đặt `enabled: False` trong index template?

**Bài tập (2 giờ) — hiệu quả nhất trong cả đồ án:**

```bash
python -m siem_correlator --dry-run --once
```

In finding ra màn hình dưới dạng JSON, không ghi alert. Chạy ngay sau khi giả lập tấn
công, rồi đọc ngược: từ mỗi trường trong JSON, chỉ ra nó sinh từ dòng code nào và từ
mục nào trong YAML. Làm 3 lần là hiểu engine.

---

# CHƯƠNG 4 — Phương pháp đánh giá

Chương này quyết định điểm chương 5 của báo cáo. Hiện tại đây là khối yếu nhất của đồ án:
`docs/bao-ve-hoi-dong.md` Câu 13 đã tự thừa nhận "cái đang có là kiểm thử chức năng,
không phải đánh giá hiệu quả phát hiện".

## 4.1 Bốn ô của ma trận nhầm lẫn — định nghĩa trong ngữ cảnh SIEM

Đừng học định nghĩa sách giáo khoa. Học định nghĩa gắn với hệ thống này.

| | Có tấn công | Không có tấn công |
|---|---|---|
| **Hệ thống báo** | TP — bắt đúng | **FP** — báo nhầm |
| **Hệ thống im** | **FN** — bỏ lọt | TN — im đúng |

- **TP**: chạy `simulate_attack.py --scenario exfil`, alert `mass_data_export_by_user` nổ.
- **FP**: chạy `benign_traffic.py`, **bất kỳ** alert tương quan nào nổ. Không có tấn công
  thì mọi alert đều sai theo định nghĩa.
- **FN**: chạy `evade_thresholds.py` hoặc `slow_insider.py`, không alert nào nổ.
- **TN**: không đếm được và không cần đếm. Số sự kiện lành tính là gần như vô hạn, nên
  mọi chỉ số dùng TN (accuracy, specificity) đều **vô nghĩa với SIEM**. Biết điều này và
  nói ra được là một điểm cộng.

## 4.2 Ba chỉ số và ý nghĩa vận hành

```
Precision = TP / (TP + FP)      trong số alert đã báo, bao nhiêu phần là thật
Recall    = TP / (TP + FN)      trong số tấn công đã xảy ra, bắt được bao nhiêu phần
F1        = 2·P·R / (P + R)     trung bình điều hoà của hai cái trên
```

Dịch sang ngôn ngữ vận hành:

- **Precision thấp** → người trực đọc 10 alert thì 8 cái là rác → sau một tuần họ ngừng
  đọc → hệ thống chết trên giấy dù vẫn chạy. Đây gọi là *alert fatigue*.
- **Recall thấp** → hệ thống im lặng trong khi bị tấn công → tệ hơn không có SIEM, vì
  doanh nghiệp tưởng mình được bảo vệ.

**Vì sao hai chỉ số đánh đổi nhau:** hạ ngưỡng (ví dụ `frequency` từ 6 xuống 3) thì bắt
được nhiều tấn công hơn (Recall tăng) nhưng cũng báo nhầm nhiều hơn (Precision giảm).
Mọi câu hỏi của hội đồng về ngưỡng đều quay về đúng chỗ này. Trả lời được cơ chế đánh đổi
thì trả lời được cả họ rule câu hỏi.

## 4.3 Chỉ số quan trọng nhất với đề tài này: FP/ngày/endpoint

F1 là chỉ số học thuật. Với một SME, con số quyết định là **số alert sai một người kiêm
nhiệm phải đọc mỗi ngày**.

```
FP/ngày = số FP đo được ÷ số giờ đo × 24
FP/ngày/endpoint = FP/ngày ÷ số endpoint
```

`scripts/eval_detection.py` đã cài sẵn ba mức diễn giải [Đã kiểm chứng — hàm `report`]:

| FP/ngày | Kết luận |
|---|---|
| > 20 | quá nhiều với SME không có SOC — dù Recall 100% vẫn vô dụng |
| 5–20 | chấp nhận được nhưng nên tinh chỉnh |
| < 5 | một người kiêm nhiệm xử lý được |

Nói được câu này trước hội đồng: *"Một hệ thống Recall 100% mà sinh 200 alert sai mỗi
ngày thì tệ hơn một hệ thống Recall 70% sinh 2 alert sai mỗi ngày, vì cái thứ nhất sẽ
không ai đọc."* Đó là góc nhìn vận hành, không phải góc nhìn sinh viên.

## 4.4 MTTD — đo từ đâu tới đâu

Mean Time To Detect = khoảng từ lúc **sự kiện đầu tiên của chuỗi tấn công** tới lúc
**alert xuất hiện**.

Trong hệ thống này, MTTD xấu nhất của lớp tương quan bằng `POLL_INTERVAL` = 60 giây,
cộng độ trễ Filebeat đẩy alert lên Indexer. Đây là hệ quả trực tiếp của lựa chọn kiến
trúc "quét theo chu kỳ thay vì realtime" — đánh đổi lấy sự đơn giản, không cần message
broker.

**Cảnh báo về phép đo:** cách đo hiển nhiên là so `window_start` với `@timestamp` của
alert. Nhưng `@timestamp` bị ghi đè mỗi vòng quét vì `doc_id` tất định. Xem Chương 7,
mục 7.3 trước khi đưa số MTTD vào báo cáo.

## 4.5 Kiểm chứng vòng tròn — hiểu VÌ SAO nó là vấn đề

Bạn viết script sinh log → viết decoder bóc log đó → viết rule bắt. Kết quả "9/9 kịch bản
phát hiện thành công" chứng minh **chuỗi xử lý thông suốt**, **không** chứng minh
**phát hiện được tấn công thật**.

Nhưng mức độ vòng tròn không đồng đều — phân biệt được ba mảng là một câu trả lời mạnh:

| Mảng | Mức vòng tròn | Vì sao |
|---|---|---|
| Log ứng dụng ERP | **hoàn toàn** | định dạng do chính bạn định nghĩa, không có ứng dụng thật |
| Log firewall | **ít hơn** | sinh log iptables đúng định dạng thật, decoder là decoder `kernel` **có sẵn của Wazuh** |
| Rule tương quan | **có** | lọc theo `rule.id` do bạn đặt |

[Đã kiểm chứng — `scripts/simulate_attack.py`, hàm `ev_fw_drop`]

Mảng thứ hai có giá trị cao hơn hẳn: nó chứng minh engine **nối được hai nguồn log khác
nhau** qua `data.srcip`, và một nửa chuỗi đó dùng ruleset của Wazuh chứ không phải của bạn.

**Ba hướng phá vòng tròn, xếp theo công sức:**

1. Đo FP trên lưu lượng lành tính (`benign_traffic.py`) — làm được ngay, đổi hẳn chất
   lượng chương đánh giá.
2. Dùng `hydra`/`nmap` thật đánh vào container SSH có agent — khi đó decoder của Wazuh,
   log thật, chỉ rule tương quan là của bạn.
3. Nhờ người khác viết kịch bản tấn công mà không cho xem rule — kiểm thử mù, phá vòng
   tròn ở mắt xích quan trọng nhất.

Hướng 1 nằm trong kế hoạch. Hướng 2 và 3 nếu không kịp thì nêu ở chương hạn chế — nêu ra
là biết mình thiếu gì, khác hẳn với không biết.

## 4.6 Quy trình đo — vì sao thứ tự quan trọng

Ba bước, **không được chồng thời gian**:

```
Bước 1 — đo FP:     chỉ chạy benign_traffic.py, không chạy tấn công
Bước 2 — đo Recall: chỉ chạy simulate_attack.py, không chạy lành tính
Bước 3 — tổng hợp
```

Trộn hai bước là **hỏng cả phép đo**, không cứu được: một alert trong khoảng trộn không
còn phân biệt được là FP hay TP. Phải đo lại từ đầu.

Sau khi `benign_traffic.py` kết thúc, **đợi thêm 2 phút** mới đóng cửa sổ (`POLL_INTERVAL`
60s + biên an toàn). Không đợi thì alert cuối chưa kịp sinh → FP bị đếm thiếu → Precision
đẹp giả.

Trước khi đo Recall, phải chờ hết cửa sổ rule dài nhất (`window: 7200` = 2 giờ trong
`smb_attack_chain.yml`) hoặc để qua đêm. Không chờ thì alert của phép đo trước lọt vào và
`eval_detection.py` sẽ in `[?] ... no ngoai ky vong`.

## 4.7 Điều kiện đo — phần không được bỏ

Mọi con số trong báo cáo phải đi kèm điều kiện đo. Thiếu thì con số mất ý nghĩa khoa học:

- FP đo trên lưu lượng lành tính **do chính mình sinh ra**, chưa phải lưu lượng thật.
- TP đo trên bộ kịch bản **do chính mình viết** (kiểm chứng vòng tròn).
- Số endpoint thật trong lab (`--endpoints 1`), không phải số ngoại suy.
- Thời lượng đo và khoảng thời gian cụ thể.

`scripts/eval_detection.py` in sẵn khối cảnh báo này ở cuối hàm `report`. **Chép vào báo
cáo, đừng bỏ.**

## 4.8 Tự kiểm tra — Chương 4

1. Định nghĩa FP trong ngữ cảnh hệ thống này, bằng một câu có nhắc tên script.
2. Vì sao SIEM không dùng chỉ số accuracy?
3. Hạ `frequency` của 100120 từ 6 xuống 3 thì Precision và Recall biến động thế nào? Vì sao?
4. Vì sao FP/ngày quan trọng hơn F1 với một SME 50 máy?
5. Kiểm chứng vòng tròn là gì? Mảng nào trong đồ án ít vòng tròn nhất và vì sao?
6. Vì sao phải đợi 2 phút sau khi `benign_traffic.py` kết thúc?

---

# CHƯƠNG 5 — Lý thuyết nền

Chương này ít điểm hơn Chương 1–3, nhưng trả lời ngập ngừng ở đây thì mất uy tín cho cả
phần sau. Học thuộc ý, không cần thuộc chữ.

## 5.1 SIEM là gì — năm chức năng

SIEM = Security Information and Event Management. Năm chức năng, thiếu một cái thì không
còn là SIEM:

| Chức năng | Trong hệ thống này |
|---|---|
| Thu thập (collection) | agent Wazuh + syslog UDP 514 |
| Chuẩn hoá (normalization) | decoder — biến dòng chữ thành trường có tên |
| Tương quan (correlation) | rule Wazuh (`frequency`) + engine Python |
| Cảnh báo (alerting) | level ≥ 3 ghi alert, active response cho 100120/100220 |
| Lưu trữ (storage/retention) | Wazuh Indexer — **retention chưa cài, xem Chương 7 mục 7.4** |

## 5.2 Phân biệt bốn loại sản phẩm

| Loại | Làm gì | Khác SIEM chỗ nào |
|---|---|---|
| **Log management** | thu, lưu, tìm kiếm log | không có tương quan, không có phát hiện |
| **SIEM** | thêm chuẩn hoá + tương quan + cảnh báo | — |
| **XDR** | SIEM + khả năng **phản ứng trực tiếp** trên endpoint, tập trung dữ liệu endpoint | dữ liệu hẹp hơn, phản ứng sâu hơn |
| **SOAR** | điều phối quy trình xử lý sự cố, playbook tự động | không tự phát hiện, nhận đầu vào từ SIEM |

Đồ án này là **SIEM**, có mầm SOAR (active response `firewall-drop` cho rule 100120 và
100220, timeout 600 giây [Đã kiểm chứng — `ossec.conf` khối `<active-response>`]), không
phải XDR.

## 5.3 Vòng đời log

```
sinh → thu → chuẩn hoá → phân tích → lưu → xoá
```

Chỉ ra được từng bước nằm ở đâu:

| Bước | Ở đâu |
|---|---|
| sinh | ứng dụng ERP, firewall, endpoint |
| thu | `<remote>` syslog UDP 514 và agent TCP 1514 |
| chuẩn hoá | `custom/decoders/local_decoder.xml` |
| phân tích | `custom/rules/local_rules.xml` + `correlation/` |
| lưu | Wazuh Indexer, index `wazuh-alerts-*` và `siem-correlated-*` |
| xoá | **chưa có** — xem Chương 7, mục 7.4 |

Bước cuối đang trống là một hạn chế thật. Nêu ở chương 6.2 của báo cáo.

## 5.4 OpenSearch aggregation — không hiểu thì không đọc được engine

Đây là phần lý thuyết **bắt buộc** vì toàn bộ `engine.py` là aggregation.

| Aggregation | Làm gì | Dùng ở đâu |
|---|---|---|
| `terms` | gom document thành nhóm theo giá trị một trường | `_run_threshold`, `_run_distinct`, `_stage_buckets` |
| `min` / `max` | mốc nhỏ nhất / lớn nhất trong nhóm | `first_seen` / `last_seen` của `sequence` |
| `top_hits` | lấy vài document mẫu trong nhóm | chứng cứ đính kèm finding |
| `cardinality` | đếm số giá trị khác nhau (xấp xỉ) | **không dùng** — repo dùng `terms` rồi đếm độ dài |

Hai tham số phải hiểu:

- **`size`** — số bucket tối đa trả về. Vượt quá thì bucket bị **bỏ âm thầm**, không có
  cảnh báo. `MAX_BUCKETS = 500` ở tầng ngoài, `50` ở tầng trong của `_run_distinct`.
- **`min_doc_count`** — chỉ trả bucket có ít nhất N document. Đây là cách repo đẩy phép
  lọc ngưỡng xuống Indexer thay vì lọc ở Python.

Và một tham số của query, không phải aggregation:

- **`"size": 0`** ở cấp cao nhất — chỉ lấy kết quả tổng hợp, **không** trả document nào.
  Đây là lý do engine xử lý được cửa sổ 2 giờ mà không kéo hàng nghìn alert về.

## 5.5 MITRE ATT&CK

- **Tactic** = mục tiêu của kẻ tấn công (Initial Access, Persistence, Exfiltration...)
- **Technique** = cách làm cụ thể. `T1110` = Brute Force.
- **Sub-technique** = biến thể. `T1110.003` = Password Spraying.

Vì sao ánh xạ rule sang ATT&CK có giá trị: nó biến "rule của em bắt được cái này" thành
"hệ thống phủ được những kỹ thuật nào trong khung tham chiếu chung của ngành" — đo được
độ phủ, so sánh được, và chỉ ra được lỗ hổng.

Kỹ thuật đang phủ trong repo [Đã kiểm chứng — `custom/rules/local_rules.xml` và
`correlation/rules/smb_attack_chain.yml`]:

| Kỹ thuật | Tên | Nơi khai báo |
|---|---|---|
| T1110 | Brute Force | rule 100120, `brute_force_then_success` |
| T1110.003 | Password Spraying | rule 100121 |
| T1046 | Network Service Discovery | rule 100220, `scan_then_login_attempt` |
| T1078 | Valid Accounts | rule 100140, `impossible_travel` |
| T1543 | Create or Modify System Process | `privilege_then_config_change` |
| T1567 | Exfiltration Over Web Service | rule 100131, `mass_data_export_by_user` |

Sáu kỹ thuật. Không nhiều, nhưng **trung thực**. Đừng khai thêm kỹ thuật mà rule không
thật sự bắt được — hội đồng hỏi "rule nào bắt T1059?" mà không chỉ ra được là mất điểm
nặng hơn nhiều so với việc phủ ít.

Lỗ hổng độ phủ dễ thấy: không có Execution, không có Persistence, không có Lateral
Movement. Lý do: hệ thống giám sát **log ứng dụng và log mạng**, không có EDR trên
endpoint. Nêu ra trước thì thành ranh giới phạm vi; bị hỏi thì thành thiếu sót.

## 5.6 Đặc thù SME — tiền đề của mọi quyết định thiết kế

Bốn ràng buộc, và hệ quả thiết kế của từng cái:

| Ràng buộc | Hệ quả trong hệ thống này |
|---|---|
| IT kiêm nhiệm, không có SOC | FP/ngày là chỉ số quan trọng nhất, không phải F1 |
| Ngân sách phần mềm bằng 0 | chọn Wazuh thay vì Splunk/QRadar |
| Hạ tầng nhỏ, một máy chủ | single-node, `number_of_replicas: 0`, không HA |
| Không ai trực 24/7 | cần active response tự động, không chỉ cảnh báo |

Mọi câu "vì sao em chọn X" đều truy về bảng này. Đây là khung trả lời chung — thuộc nó
thì trả lời được cả những câu chưa gặp bao giờ.

## 5.7 Tự kiểm tra — Chương 5

1. SIEM khác log management chỗ nào? Trả lời trong 3 câu, không dùng từ mơ hồ.
2. Đồ án này có phải XDR không? Vì sao?
3. `"size": 0` trong query làm gì và vì sao nó quan trọng với hiệu năng?
4. Tactic, technique, sub-technique khác nhau thế nào? Cho ví dụ từ repo.
5. Hệ thống phủ mấy kỹ thuật ATT&CK? Thiếu nhóm nào và vì sao thiếu?

---

# CHƯƠNG 6 — Vận hành

Chương này ít bị hỏi trong phần lý thuyết, nhưng **bị hỏi ngay lập tức nếu demo trục trặc**.
Mục tiêu: hiểu đủ để chẩn đoán tại chỗ, không phải chạy script như bùa.

## 6.1 Bốn container và vai trò

| Container | Cổng | Vai trò |
|---|---|---|
| `wazuh.manager` | 1514/tcp, 1515/tcp, 514/udp, 55500→55000 | nhận log, chạy decoder + rule, sinh alert |
| `wazuh.indexer` | 9200 | OpenSearch — lưu và truy vấn alert |
| `wazuh.dashboard` | 443→5601 | giao diện |
| `correlator` | — | engine Python, chỉ gọi ra, không mở cổng |

[Đã kiểm chứng — `docker/single-node/docker-compose.yml`]

Bốn cổng của manager, mỗi cổng một việc:

- **1514/tcp** — agent gửi sự kiện (đã mã hoá)
- **1515/tcp** — `authd`, agent đăng ký lần đầu
- **514/udp** — syslog từ thiết bị mạng (thiết bị không cài được agent)
- **55500** — REST API

## 6.2 `vm.max_map_count` — câu hỏi kinh điển

OpenSearch dùng `mmap` để ánh xạ chỉ mục Lucene vào bộ nhớ ảo. Mặc định của Linux
(65530) quá thấp → container chết khi khởi động. Phải đặt:

```bash
sudo sysctl -w vm.max_map_count=262144
```

Đây là **thiết lập của máy chủ (kernel), không phải của container** — nên đặt lại sau mỗi
lần khởi động máy, hoặc ghi vào `/etc/sysctl.conf`. Biết được điểm này là biết ranh giới
giữa cái Docker giải quyết được và cái nó không.

## 6.3 TLS và chứng chỉ

`generate-certs.yml` sinh bộ chứng chỉ trước khi stack lên. Wazuh bắt buộc TLS giữa
manager ↔ indexer ↔ dashboard, không tắt được.

Thư mục `config/certs/` nằm trong `.gitignore` — **đúng**, vì chứa khoá riêng.
[Đã kiểm chứng — `.gitignore` dòng 2–3]

Nhưng correlator đặt `INDEXER_VERIFY_CERTS: "false"` trong khi manager dùng
`FILEBEAT_SSL_VERIFICATION_MODE: full`. Không nhất quán — xem Chương 7, mục 7.5.

## 6.4 Thu thập log — hai đường vào

**Đường 1: agent.** Cài trên máy trạm Windows/Linux. Đăng ký qua `authd` cổng 1515, sau
đó gửi sự kiện qua 1514/tcp đã mã hoá.

`ossec.conf` đặt `<use_password>no</use_password>` → **ai tới được cổng 1515 đều đăng ký
được agent**. Chấp nhận trong lab, nhưng phải ghi rõ là hạn chế bảo mật trong báo cáo.
[Đã kiểm chứng — `ossec.conf` dòng 40]

**Đường 2: syslog UDP 514.** Cho thiết bị không cài được agent (router, switch, firewall).
Hạn chế IP nguồn bằng ba dải riêng:

```xml
<allowed-ips>172.16.0.0/12</allowed-ips>
<allowed-ips>192.168.0.0/16</allowed-ips>
<allowed-ips>10.0.0.0/8</allowed-ips>
```

**Câu hỏi có thể gặp: syslog UDP không xác thực, sao tin được?** Trả lời thẳng: không
tin được về mặt mật mã. `allowed-ips` chỉ lọc theo IP nguồn, mà IP nguồn UDP thì giả mạo
được. Đây là hạn chế cố hữu của syslog, không phải của đồ án. Giảm thiểu bằng cách chỉ
cho phép dải nội bộ và đặt manager trong vùng mạng quản trị.

## 6.5 Các mô-đun đang bật và chu kỳ chạy

[Đã kiểm chứng — `ossec.conf`]

| Mô-đun | Chu kỳ | Việc |
|---|---|---|
| `syscheck` (FIM) | 43200s (12h) + realtime | theo dõi thay đổi file |
| `sca` | 43200s | đánh giá cấu hình theo chuẩn |
| `vulnerability-detection` | — | đối chiếu phần mềm với CSDL lỗ hổng |
| `active-response` | theo sự kiện | `firewall-drop` cho rule 100120, 100220, timeout 600s |

FIM bật `realtime="yes"` trên `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/boot`
và `C:\Windows\System32\drivers\etc`.

**Hệ quả cho phép đo hiệu năng:** trong lab không có endpoint thật nên FIM realtime gần
như không sinh log. Trên máy thật sẽ sinh **nhiều hơn hẳn**. Đây là lý do thứ nhất trong
ba lý do khiến phép ngoại suy của `measure_capacity.sh` có thể sai đáng kể — script tự in
cảnh báo này.

## 6.6 Chuỗi khởi động và vì sao correlator phải chờ

```python
for attempt in range(30):
    if client.ping():
        break
    log.info("Cho Wazuh Indexer... (%d/30)", attempt + 1)
    time.sleep(10)
```

30 lần × 10 giây = chờ tối đa 5 phút. `depends_on` của Docker chỉ đảm bảo container
**đã khởi động**, không đảm bảo dịch vụ bên trong **đã sẵn sàng**. OpenSearch mất hàng
chục giây để nạp chỉ mục. Không có vòng chờ này thì correlator chết ngay lần đầu và
`restart` liên tục.

Đây là ví dụ tốt cho câu hỏi "em xử lý phụ thuộc giữa các dịch vụ thế nào".

## 6.7 Chẩn đoán khi demo hỏng

Thứ tự kiểm tra, từ rẻ đến đắt:

```bash
docker compose -f docker/single-node/docker-compose.yml ps
```

Container nào không `Up` thì đọc log của container đó trước, đừng đoán.

```bash
docker compose -f docker/single-node/docker-compose.yml logs --tail=50 correlator
```

Tìm dòng `Vong quet xong: N alert tuong quan, X.Xs`. Không có dòng này nghĩa là correlator
chưa chạy được vòng nào.

Có sẵn `scripts/troubleshoot_demo.sh` cho tình huống dashboard tương quan trống. **Đọc nó
trước khi demo** để biết nó kiểm tra gì — chạy mà không hiểu thì khi nó báo lỗi vẫn bí.

Ba nguyên nhân thường gặp khi dashboard tương quan trống:

1. Correlator chưa chạy đủ một vòng (chờ 60s).
2. Không có alert Wazuh nào trong cửa sổ → engine không có gì để tương quan. Kiểm tra
   `wazuh-alerts-*` trước, đừng nhìn `siem-correlated-*`.
3. Index pattern `siem-correlated-*` chưa được tạo trong Dashboard.

## 6.8 Tự kiểm tra — Chương 6

1. Vẽ kiến trúc bốn container kèm cổng, không nhìn tài liệu.
2. `vm.max_map_count` là thiết lập của ai — container hay máy chủ? Hệ quả là gì?
3. Vì sao cần cả 1514 lẫn 1515?
4. Correlator chờ Indexer bao lâu, và vì sao `depends_on` không đủ?
5. Dashboard tương quan trống — ba chỗ kiểm tra theo thứ tự nào?
6. `<use_password>no</use_password>` gây rủi ro gì?

**Bài tập (90 phút).** Tắt toàn bộ stack, bật lại, quan sát thứ tự container lên và đọc
log correlator trong lúc nó chờ.

---

# CHƯƠNG 7 — Những điểm không hợp lý trong repo

Danh sách này kiểm chứng lại bảng "Khoảng trống đã biết" trong
`docs/adr/0001-kien-truc-tong-the.md` mục 6 (viết khi repo **chưa** `git init`), cập nhật
theo trạng thái hiện tại, và bổ sung các điểm chưa được ghi ở đâu cả.

**Cách dùng chương này:** mỗi mục là một câu hỏi phản biện tiềm năng. Sửa được thì sửa;
không kịp sửa thì đưa vào chương hạn chế của báo cáo. **Điều tệ nhất là không biết nó tồn
tại.**

Xếp theo mức độ: Cao → Trung bình → Thấp.

---

## MỨC CAO

### 7.1 Mật khẩu mặc định đã nằm trong lịch sử git

**Trạng thái:** ADR ghi "repo chưa `git init`; nếu init thì credentials vào lịch sử ngay".
Repo **đã** được `git init` và `docker/single-node/.env` **đang được git theo dõi**.

[Đã kiểm chứng — `git ls-files` liệt kê `docker/single-node/.env`; file chứa
`INDEXER_PASSWORD`, `DASHBOARD_PASSWORD`, `API_PASSWORD`]

**Vì sao nghiêm trọng:** thêm `.env` vào `.gitignore` bây giờ **không xoá được nó khỏi
lịch sử**. Nếu repo được đẩy lên GitHub — kể cả private rồi sau đó public — mật khẩu đi
theo.

**Giảm nhẹ:** hiện chỉ có **một** commit và [Suy luận] repo có vẻ chưa được đẩy lên đâu,
nên xử lý lúc này còn rẻ. Đây cũng là mật khẩu mặc định của môi trường lab, không phải
mật khẩu sản xuất — nhưng lập luận đó không dùng được trước hội đồng, vì thói quen mới là
thứ bị đánh giá.

**Cách xử lý, theo thứ tự:**

1. Thêm `docker/single-node/.env` vào `.gitignore`.
2. Bỏ theo dõi file: `git rm --cached docker/single-node/.env`.
3. Tạo `docker/single-node/.env.example` với giá trị giả, **commit file này** để người
   khác biết cần những biến gì.
4. Vì mới có một commit, cách sạch nhất là tạo lại lịch sử từ đầu. Đây là thao tác **xoá
   lịch sử hiện tại, không hoàn tác được** — sao lưu thư mục trước khi làm, và chỉ làm khi
   chắc chắn chưa đẩy lên remote nào.
5. Đổi toàn bộ mật khẩu trong `.env` trước khi triển khai ở bất kỳ đâu ngoài máy cá nhân.

**Nếu bị hỏi:** trả lời thẳng là đã phát hiện và đã xử lý, kèm việc tách `.env.example`.
Đây là câu trả lời tốt — nó cho thấy hiểu về quản lý bí mật, không chỉ hiểu về SIEM.

### 7.2 Điều kiện thứ tự của `sequence` quá lỏng

```python
ordered = all(timeline[i]["first"] <= timeline[i+1]["last"] ...)
```

[Đã kiểm chứng — `correlation/siem_correlator/engine.py`, `_run_sequence`]

Chi tiết và ví dụ dương tính giả: xem Chương 3, mục 3.4.

**Cách sửa:** đổi thành `first[i] <= first[i+1]`. Một dòng.

**Nhưng cân nhắc trước khi sửa:** nếu đã đo Recall với điều kiện cũ thì sửa xong phải
**đo lại toàn bộ**, vì điều kiện chặt hơn có thể làm một số kịch bản demo không nổ nữa.
Sửa thì sửa **trước** tuần đo, đừng sửa giữa chừng.

Giá trị nếu sửa được: biến một hạn chế thừa nhận thành một bảng "trước/sau" trong chương
đánh giá — chứng minh được rằng bạn hiểu điểm yếu đủ sâu để sửa nó.

### 7.3 `@timestamp` bị ghi đè mỗi vòng quét — làm sai phép đo MTTD

**Đây là điểm chưa được ghi ở bất kỳ tài liệu nào trong repo.**

`doc_id` tất định khiến mỗi vòng quét ghi đè **toàn bộ** document cũ
(`PUT /{index}/_doc/{id}`, `indexer.py::index_doc`). Trong khi đó `to_document()` đặt:

```python
"@timestamp": self.window_end.isoformat(),
```

`window_end` = thời điểm quét hiện tại. Nên chừng nào điều kiện rule còn thoả, alert còn
được ghi đè và `@timestamp` của nó còn **trôi về phía trước** theo từng vòng 60 giây.

[Suy luận — đọc từ `engine.py::Finding.to_document`, `indexer.py::index_doc`,
`__main__.py`; chưa dựng thực nghiệm đo độ trôi]

**Hậu quả cụ thể:** `docs/bao-ve-hoi-dong.md` Câu 13 đề xuất đo MTTD bằng
`window_start` so với `@timestamp` của alert. Với cơ chế hiện tại, hiệu số đó **không phải
độ trễ phát hiện** mà là khoảng cách tới lần ghi đè **cuối cùng** — MTTD bị thổi phồng,
có thể lên tới cả độ dài cửa sổ rule.

Nếu không xử lý, con số MTTD trong chương 5 sẽ sai và **hội đồng có thể bắt được bằng
cách hỏi "vì sao MTTD gần bằng đúng window của rule?"**.

**Ba cách xử lý, chọn một:**

| Cách | Làm gì | Đánh đổi |
|---|---|---|
| A | Thêm trường `detected_at`, chỉ ghi lần đầu | phải đọc document cũ trước khi ghi — thêm một lượt gọi |
| B | Dùng `op_type=create`, đã tồn tại thì bỏ qua | `event_count` không cập nhật nữa |
| C | Không sửa code, đo MTTD từ log của correlator | không sửa gì, nhưng phải giải thích cách đo trong báo cáo |

Cách C rẻ nhất và đủ dùng cho đồ án: dòng `Vong quet xong` trong log correlator có mốc
thời gian, đối chiếu với thời điểm gửi sự kiện của `simulate_attack.py`.

**Dù chọn cách nào, phải ghi rõ cách đo MTTD trong báo cáo.** Đây là loại chi tiết mà hội
đồng dùng để phân biệt người tự làm với người chép.

### 7.4 Không có chính sách lưu trữ và xoá dữ liệu

[Đã kiểm chứng — `grep -rn "ism|retention|rollover"` trên `docker/` và `scripts/deploy.sh`
không ra kết quả nào]

`wazuh-alerts-*` và `siem-correlated-*` **mọc vô hạn**. Đề cương báo cáo mục 3.3 có mục
"vòng đời dữ liệu" nhưng code chưa hiện thực.

**Vì sao đây là vấn đề với đúng đề tài này:** đề tài hướng tới SME, mà ràng buộc lớn nhất
của SME là ổ đĩa và tiền. Một hệ thống giám sát tự lấp đầy ổ đĩa rồi chết là hỏng đúng
vào điểm mà đề tài nhận là thế mạnh.

Câu hỏi gần như chắc chắn: *"Chạy một năm thì bao nhiêu GB, và khi đầy ổ thì sao?"*

**Cách xử lý tối thiểu:** cài một ISM policy xoá index cũ hơn N ngày. Nếu không kịp, phải
nêu ở chương hạn chế **kèm con số ước lượng** từ `measure_capacity.sh` — có ước lượng thì
ít nhất chứng minh được là đã nghĩ tới.

---

## MỨC TRUNG BÌNH

### 7.5 `INDEXER_VERIFY_CERTS: "false"` — không nhất quán

[Đã kiểm chứng — `docker/single-node/docker-compose.yml`, khối `correlator`]

Manager dùng `FILEBEAT_SSL_VERIFICATION_MODE: full`, correlator thì tắt xác minh chứng
chỉ. Đã sinh sẵn root CA mà không dùng.

Hệ quả: correlator không phát hiện được tấn công người-đứng-giữa giữa nó và Indexer.
Trong lab một máy thì rủi ro thực tế thấp, nhưng nó là **điểm không nhất quán trong thiết
kế** — và hội đồng chấm sự nhất quán.

**Cách sửa:** mount root CA vào container correlator, đặt `INDEXER_VERIFY_CERTS: "true"`.
Sửa nhanh, ăn điểm, rủi ro thấp.

### 7.6 `ManagerSink` và nhóm rule 100900–100903 hiện không chạy

[Đã kiểm chứng — khối `correlator` trong `docker-compose.yml` không có biến
`MANAGER_SOCKET`; `config.py` đặt `manager_socket=None` khi biến vắng mặt; `__main__.py`
chỉ thêm `ManagerSink` khi `settings.manager_socket` khác `None`]

Nghĩa là: 4 rule Wazuh (100900–100903) đã viết, một sink đã viết, nhưng **đường đi này
chưa từng chạy và chưa được kiểm chứng**. Alert tương quan hiện chỉ vào thẳng Indexer,
không đi qua ruleset, nên **không kích hoạt được active response hay email**.

**Đây là loại điểm dễ bị bắt nhất**: có code, có rule, nhìn như đã làm xong. Nếu hội đồng
hỏi "alert tương quan có kích hoạt phản ứng tự động không?" mà trả lời "có" thì sai sự thật.

**Hai lựa chọn:**

- Bật lên và kiểm chứng: mount socket của manager, đặt `MANAGER_SOCKET`, chạy thử, chụp
  màn hình alert level 14 nhóm `correlation`. Nếu làm được thì đây là một mục đẹp trong
  chương 4.
- Không kịp thì **nói rõ là chưa bật** và đưa vào hướng phát triển.

### 7.7 Engine nuốt mọi ngoại lệ — hỏng thì im lặng

```python
try:
    findings = runner(rule, start, end)
except Exception as exc:
    log.error("Rule '%s' loi khi chay: %s", rule.id, exc)
    return []
```

[Đã kiểm chứng — `engine.py::run`]

Một rule lỗi (sai tên trường, Indexer trả 4xx, mapping đổi) chỉ ghi một dòng log rồi trả
danh sách rỗng. Từ góc nhìn dashboard, "rule hỏng" và "không có tấn công" **trông giống
hệt nhau**.

Đây đúng là loại lỗi mà chuỗi rule 100101–100106 được thiết kế để chống ở tầng decoder —
nhưng ở tầng engine thì chưa có cơ chế tương đương. **Không nhất quán về triết lý thiết
kế**, và hội đồng tinh ý sẽ thấy.

**Ảnh hưởng tới phép đo:** nếu một rule lỗi trong lúc đo Recall, bạn sẽ ghi nhận FN và đi
tìm nguyên nhân ở ngưỡng rule, trong khi nguyên nhân thật nằm ở query.

**Cách sửa rẻ:** đếm số rule lỗi trong một vòng quét, ghi vào dòng tổng kết
`Vong quet xong: N alert, M rule loi, X.Xs`. Vài dòng code, và biến một điểm yếu thành một
mục đáng nói trong báo cáo.

### 7.8 `erp.rows` lưu dạng chuỗi — tầng tương quan không so sánh số được

[Đã kiểm chứng — comment rule 100131 nêu thẳng hạn chế này]

Trên Indexer `data.erp.rows` là text, nên `data.erp.rows__gte: 10000` trong YAML sẽ so
sánh **theo từ điển** chứ không theo số — `"9999" > "10000"` theo thứ tự chuỗi.

Hệ quả: ngưỡng số dòng xuất **chỉ** áp được ở tầng rule Wazuh (100131, dùng pcre2), không
áp được ở tầng tương quan. Đang là một giới hạn thật của thiết kế, chưa phải lỗi.

**Cách sửa đúng:** khai báo index template cho `wazuh-alerts-*` ép `data.erp.rows` thành
kiểu số. Đụng vào template của Wazuh nên rủi ro cao hơn lợi ích trước ngày bảo vệ —
[Suy luận] khuyến nghị **ghi vào hạn chế**, không sửa.

### 7.9 `impossible_travel` đặt tên sai bản chất

```yaml
- id: impossible_travel
  type: distinct
  group_by: data.dstuser
  distinct_field: data.srcip
  min_cardinality: 3
```

Rule này đếm **số IP khác nhau**, không có bất kỳ dữ liệu địa lý nào. "Impossible travel"
trong ngành có nghĩa cụ thể: đăng nhập từ hai vị trí địa lý mà khoảng cách chia thời gian
vượt tốc độ di chuyển khả thi. Rule ở đây không làm việc đó.

Phần `description` mô tả đúng bản chất ("thường là tài khoản dùng chung hoặc thông tin
đăng nhập bị rò rỉ") — nhưng **cái tên thì hứa nhiều hơn cái nó làm**, và hội đồng đọc
tên trước.

**Cách sửa rẻ nhất và tốt nhất:** đổi tên thành `multi_ip_login` hoặc
`concurrent_multi_ip_login`. Sửa một dòng YAML, mất một điểm yếu.

Nếu giữ tên cũ thì phải **chủ động giải thích** ngay khi nhắc tới rule này, đừng để bị hỏi.

### 7.10 Độ phủ MITRE mỏng ở tầng Wazuh

[Đã kiểm chứng — `grep -c "<mitre>" custom/rules/local_rules.xml` = 5, trên khoảng 19 rule
có level > 0. Tầng tương quan tốt hơn: 6/7 rule có trường `mitre`]

Rule không khai báo `<mitre>` thì không hiện lên bảng ATT&CK của Wazuh Dashboard — tức là
một trong những ảnh chụp đẹp nhất cho báo cáo đang bị bỏ trống một nửa.

Các rule đáng bổ sung: 100122 (đăng nhập ngoài giờ), 100130 (xuất dữ liệu nhạy cảm),
100150 (sửa giá — gian lận nghiệp vụ), 100901–100903.

Riêng 100141 (cấp quyền admin) kế thừa ngữ cảnh từ 100140 đã có `T1078` — bổ sung thì tốt,
không bổ sung cũng giải thích được.

**Cảnh báo:** gán kỹ thuật **sai** còn tệ hơn để trống. Tra kỹ trước khi gán.

### 7.11 Các rule ID của SSH trong rule tương quan chưa được kiểm chứng

`brute_force_then_success`, `impossible_travel`, `scan_then_login_attempt` đều liệt kê
rule ID có sẵn của Wazuh cho SSH và Windows: `5710`, `5712`, `5715`, `60106`, `60122`,
`40112`, `5402`, `5403`, `60112`.

[Suy luận] Lab hiện không có agent SSH hay Windows thật gửi log, nên các nhánh này **chưa
bao giờ khớp trong thực tế**. Chúng là suy đoán dựa trên tài liệu Wazuh, chưa phải kết quả
kiểm chứng.

Comment trong YAML cho thấy ít nhất `40112` đã được tra cứu cẩn thận ("SSH that: 5715
khong phat, 40112 phat, co san data.srcip") — nhưng tra cứu khác với chạy thử.

**Nếu bị hỏi "rule này có chạy trên log SSH thật không?":** trả lời trung thực là đã ánh
xạ theo tài liệu, chưa kiểm chứng bằng log SSH thật vì lab không có nguồn đó. Đừng khẳng
định là chạy được.

**Cơ hội:** dựng một container SSH có agent rồi dùng `hydra` đánh vào là cách rẻ nhất để
**phá kiểm chứng vòng tròn** (Chương 4, mục 4.5, hướng 2) **và** kiểm chứng luôn các rule
ID này. Một việc, hai giá trị.

### 7.12 Vòng phản hồi tiềm ẩn giữa `noisy_agent_high_severity` và `ManagerSink`

```yaml
- id: noisy_agent_high_severity
  type: threshold
  group_by: agent.name
  min_count: 20
  filter:
    rule.level__gte: 10
```

Rule này đếm alert Wazuh level ≥ 10. Trong khi đó, nếu `ManagerSink` được bật (mục 7.6),
alert tương quan sẽ quay ngược vào manager và khớp rule 100901–100903 ở level **10, 12, 14**
— tức là **vượt ngưỡng lọc của chính rule này**.

[Suy luận — đọc từ `smb_attack_chain.yml`, `sinks.py`, và nhóm rule 100900 trong
`local_rules.xml`; hiện chưa xảy ra vì `ManagerSink` chưa bật, nên chưa quan sát được]

Kịch bản: alert tương quan → vào manager → thành alert level 12 → lần quét sau bị
`noisy_agent_high_severity` đếm → sinh alert tương quan mới → lặp lại.

**Hiện chưa xảy ra** vì `ManagerSink` chưa bật. Nhưng nếu bật nó theo khuyến nghị ở mục
7.6 mà không thêm điều kiện loại trừ thì rủi ro là có thật.

**Cách phòng:** thêm loại trừ nhóm `correlation` vào filter của rule này — cần trường
`exclude` (chưa có, xem `docs/bao-ve-hoi-dong.md` Câu 14). Hoặc đơn giản hơn: chỉ bật
`ManagerSink` cho severity `critical`.

Đây là loại lỗi kiến trúc đáng nói trong báo cáo: **hệ thống giám sát tự giám sát chính nó
thì phải cẩn thận với vòng lặp.**

---

## MỨC THẤP

### 7.13 `lookback_slack` là cấu hình chết

[Đã kiểm chứng — `grep -rn lookback_slack` chỉ ra `config.py` (2 chỗ) và 3 tài liệu;
không nơi nào trong `engine.py` dùng tới]

Biến được khai báo, đọc từ môi trường, có mặc định 60 giây, và **không có tác dụng gì**.

**Ý định ban đầu** (suy ra từ tên và từ `docs/bao-ve-hoi-dong.md` Câu 7): dời cả cửa sổ
truy vấn lùi lại một khoảng, để những sự kiện **đến muộn** (Filebeat trễ, đồng hồ lệch)
kịp vào Indexer trước khi engine quét qua khoảng thời gian đó.

Vấn đề nó định giải quyết là **có thật**: engine quét `[now - window, now)`. Một sự kiện
xảy ra lúc `now - 5s` nhưng tới Indexer lúc `now + 3s` thì vòng quét này bỏ sót, và vòng
sau thì nó đã không còn ở mép cửa sổ.

**Cách sửa — 2 dòng:**

```python
end = (now or datetime.now(timezone.utc)) - timedelta(seconds=self.lookback_slack)
start = end - timedelta(seconds=rule.window)
```

Đánh đổi: MTTD tăng thêm đúng `lookback_slack` giây.

**Nếu bị hỏi "biến này để làm gì?"** — trả lời trung thực là đã thiết kế nhưng chưa nối
vào, và nêu được cả vấn đề nó định giải quyết lẫn đánh đổi. Câu trả lời đó tốt hơn nhiều
so với việc giả vờ nó đang chạy.

### 7.14 `MAX_BUCKETS = 500` cắt cụt trong im lặng

Quá 500 khoá trong một cửa sổ thì khoá thừa bị bỏ, **không cảnh báo**. Tương tự với
`size: 50` ở tầng trong của `_run_distinct`.

Với SME 40–50 endpoint thì 500 là thừa. Nhưng "thừa ở quy mô hiện tại" không phải câu trả
lời đầy đủ — câu trả lời đầy đủ là: *"Vượt ngưỡng thì mất khoá âm thầm; cách phát hiện là
so `sum_other_doc_count` mà OpenSearch trả về với 0."*

Biết tên `sum_other_doc_count` và biết nó dùng để làm gì là dấu hiệu rõ ràng của người
thật sự hiểu aggregation.

### 7.15 Kiểm thử chỉ phủ `engine.py`

`correlation/tests/` chỉ có `test_engine.py`. `rules.py` (có logic `validate` đáng test),
`sinks.py`, `indexer.py` chưa có test. Không có CI, không có lint.

`scripts/negative_rule_test.sh` thoát với mã 1 khi có ca hỏng → **cắm vào CI được ngay**.
Nêu điều này ở phần hướng phát triển là một câu trả lời gọn cho "hướng phát triển tiếp theo
là gì".

### 7.16 `test_rules.sh` gắn cứng tên container

```bash
CONTAINER="${CONTAINER:-siem-raw-wazuh.manager-1}"
```

Tên container do Docker Compose sinh ra từ tên thư mục dự án. Đổi tên thư mục là script
hỏng. Có thể ghi đè bằng biến môi trường nên không nghiêm trọng, nhưng nếu demo ở máy khác
thì dễ vấp đúng lúc không nên vấp.

### 7.17 Dashboard phải nhập tay

`dashboards/siem-correlated-dashboard.ndjson` phải import thủ công qua giao diện;
`scripts/deploy.sh` không tự làm. Một bước thủ công trong quy trình được mô tả là "triển
khai bằng một lệnh".

Trước ngày bảo vệ, nguy cơ thật là **quên bước này khi dựng lại lab** rồi dashboard trống
lúc demo. Ghi vào `docs/so-tay-van-hanh.md` phần danh sách kiểm tra trước demo.

### 7.18 `.claude` bị loại khỏi git

[Đã kiểm chứng — `.gitignore` có dòng `.claude`; `git ls-files` không có file nào trong đó]

Thư mục này chứa 6 skill viết riêng cho dự án (`siem-stack`, `wazuh-rule`,
`correlation-rule`, `detection-test`, `demo-attack`, `thesis-docs`). Đó là **tài sản của
dự án**, không phải rác của IDE — mất máy là mất.

Không liên quan tới điểm bảo vệ, nhưng nên đưa vào git.

### 7.19 Tài liệu kiến trúc không khớp hệ thống thật

`docs/achitechture/osint-user-scanner-siem-integration-plan.md` (1507 dòng) mô tả kiến
trúc Kafka + OCSF + worker riêng — **không phải** kiến trúc đang chạy.

ADR ghi file này nằm ở thư mục gốc; hiện nó đã được chuyển vào `docs/achitechture/`, nên
rủi ro hiểu nhầm đã giảm. Nhưng nếu hội đồng đọc repo và mở trúng file này thì vẫn có thể
hỏi về Kafka.

**Khuyến nghị:** thêm một dòng ở đầu file — *"Tài liệu định hướng tương lai, KHÔNG mô tả
hệ thống hiện tại. Kiến trúc đang chạy: xem `docs/adr/0001-kien-truc-tong-the.md`."*
Một dòng, hết rủi ro.

### 7.20 File `.deb` 10.7 MB trong thư mục làm việc

`wazuh-agent_4.9.2-1_amd64.deb` nằm ở thư mục gốc. Đã bị `.gitignore` chặn nên không vào
git, nhưng nó không nên nằm ở gốc dự án. Chuyển vào một thư mục `vendor/` hoặc xoá và ghi
đường dẫn tải về trong sổ tay vận hành.

---

## 7.21 Bảng tổng hợp — ưu tiên xử lý trước ngày bảo vệ

| # | Vấn đề | Mức | Công sức | Nên làm |
|---|---|---|---|---|
| 7.1 | `.env` trong lịch sử git | Cao | 30 phút | **Làm ngay** |
| 7.3 | `@timestamp` ghi đè → MTTD sai | Cao | 1h (cách C: 0) | **Làm trước khi đo** |
| 7.2 | thứ tự `sequence` lỏng | Cao | 1 dòng + đo lại | Làm trước tuần đo |
| 7.9 | `impossible_travel` sai tên | TB | 5 phút | **Làm ngay** |
| 7.5 | `INDEXER_VERIFY_CERTS` | TB | 30 phút | Nên làm |
| 7.10 | MITRE mỏng | TB | 2h | Nên làm |
| 7.19 | tài liệu Kafka gây hiểu nhầm | Thấp | 5 phút | **Làm ngay** |
| 7.7 | engine nuốt ngoại lệ | TB | 30 phút | Nếu còn thời gian |
| 7.4 | không có retention | Cao | 2h | Nếu không kịp thì nêu hạn chế |
| 7.6 | `ManagerSink` chưa bật | TB | 2h | Nếu không kịp thì nói rõ là chưa bật |
| còn lại | — | Thấp | — | Đưa vào chương hạn chế |

**Bốn việc dưới 30 phút mỗi việc (7.1, 7.9, 7.19, và cách C của 7.3) nên làm trong tuần
này.** Chúng loại bỏ bốn câu hỏi phản biện với chi phí gần bằng không.

---

# PHỤ LỤC — Bộ câu hỏi tự kiểm tra tổng hợp

Nhờ một người khác hỏi ngẫu nhiên 10 câu. Trả lời không nhìn tài liệu, mỗi câu dưới 2 phút.

**Decoder**
1. `offset="after_parent"` làm gì?
2. Trường tĩnh và trường động khác nhau thế nào? Dùng nhầm thì lỗi gì?
3. Vì sao đặt tiền tố `erp.`?

**Rule Wazuh**
4. Vì sao 100200 phải là level 2 chứ không phải 0?
5. Vì sao phải neo hai đầu cho `^OK$`? Hậu quả nếu không neo?
6. Cơ chế 100101–100106 chống lỗi gì, và vì sao không dùng được `negate`?
7. Brute force và spraying khác nhau ở thẻ nào?

**Engine**
8. Vẽ luồng từ vòng lặp tới alert trong Indexer.
9. `threshold` và `distinct` khác nhau thế nào? Ví dụ dữ liệu phân biệt.
10. `doc_id` giải quyết gì, không giải quyết gì?
11. Nêu ví dụ dương tính giả của điều kiện thứ tự, kèm mốc thời gian.

**Đánh giá**
12. Định nghĩa FP trong hệ thống này.
13. Vì sao SIEM không dùng accuracy?
14. Hạ ngưỡng thì Precision và Recall biến động thế nào?
15. Kiểm chứng vòng tròn là gì? Mảng nào ít vòng tròn nhất?

**Lý thuyết và vận hành**
16. SIEM khác log management chỗ nào?
17. `vm.max_map_count` là thiết lập của ai?
18. Correlator chờ Indexer thế nào và vì sao `depends_on` không đủ?
19. Dashboard tương quan trống — kiểm tra ba chỗ nào?

**Điểm yếu — phải tự nêu được, đây là nhóm câu quan trọng nhất**
20. Kể ba hạn chế của hệ thống mà bạn tự phát hiện, kèm cách sửa và đánh đổi của từng cách.

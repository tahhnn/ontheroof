# ADR-0001: Kiến trúc tổng thể và bố cục mã nguồn SIEM-raw

- **Trạng thái**: Đã chấp nhận
- **Ngày**: 2026-09-04
- **Phạm vi**: Toàn bộ repository `SIEM-raw`
- **Mục đích của tài liệu**: Bản neo kiến trúc. Đọc file này trước khi sửa bất kỳ tầng nào; mọi phiên làm việc sau nên dẫn chiếu tới đây thay vì mô tả lại cấu trúc.

---

## 1. Bối cảnh

Đồ án tốt nghiệp: xây dựng hệ thống giám sát an ninh (SIEM) cho doanh nghiệp vừa và nhỏ (SMB) tại Việt Nam.

Ràng buộc chi phối mọi quyết định kiến trúc:

| Ràng buộc | Hệ quả |
|---|---|
| Chi phí phần mềm bằng 0 | Chỉ dùng thành phần mã nguồn mở |
| Một người kiêm nhiệm vận hành | Ưu tiên ít thành phần, ít phụ thuộc, có sổ tay vận hành |
| Hạ tầng nhỏ (1 máy chủ, RAM ≥ 6 GB) | Một node, không HA, `number_of_replicas: 0` |
| Phải bảo vệ được trước hội đồng | Phần tự viết phải giải thích được từng dòng, không giấu logic trong thư viện bên thứ ba |
| Ứng dụng nội bộ có log riêng | Bắt buộc tự viết decoder — Wazuh không hiểu sẵn |

Nhu cầu kỹ thuật cốt lõi: rule Wazuh đơn lẻ chỉ nhìn được một loại sự kiện trong cửa sổ ngắn. Các chuỗi tấn công thật (dò mật khẩu → đăng nhập thành công → xuất dữ liệu) trải qua nhiều loại sự kiện trong nhiều giờ. Cần thêm một lớp phát hiện nữa.

---

## 2. Quyết định

### 2.1. Nền tảng: Wazuh 4.9.2 chạy Docker Compose một node

Chọn Wazuh thay vì Graylog / ELK thuần / Security Onion / Splunk Free vì có sẵn agent, ruleset, FIM, SCA, vulnerability detection và active response trong một sản phẩm — giảm số thành phần người vận hành phải học.

### 2.2. Ba lớp phát hiện chồng nhau

| Lớp | Nằm ở | Bắt được gì | Giới hạn cố hữu |
|---|---|---|---|
| 1. Ruleset Wazuh có sẵn | image manager | Tấn công đã biết trên OS và dịch vụ phổ biến | Không hiểu log ứng dụng riêng |
| 2. Decoder + rule tự viết | `custom/` | Sự kiện ứng dụng ERP nội bộ, brute force, spraying, xuất dữ liệu, leo thang quyền | Một nguồn log, cửa sổ ngắn (giây → phút) |
| 3. Engine tương quan | `correlation/` | Chuỗi hành vi xuyên nhiều nguồn log, cửa sổ 15 phút → 2 giờ | Chạy theo chu kỳ, không realtime |

Lớp 3 là đóng góp kỹ thuật chính của đồ án.

### 2.3. Correlator là tiến trình riêng, đọc/ghi qua REST của Indexer

Không nhúng vào manager, không dùng plugin. Correlator poll `wazuh-alerts-*`, sinh finding, ghi vào index riêng `siem-correlated-*`.

Lý do: tách failure domain (correlator chết không kéo manager chết), ngôn ngữ rule độc lập với ruleset XML của Wazuh, và toàn bộ logic nằm trong Python đọc được — phục vụ chương 4.6 của báo cáo.

### 2.4. Rule tương quan viết bằng YAML, chỉ ba kiểu

`threshold` (đếm theo khoá), `distinct` (đếm số giá trị khác nhau), `sequence` (nhiều giai đoạn đúng thứ tự trên cùng khoá join).

Ba kiểu này phủ hết bảy kịch bản SMB đã xác định. Không thêm kiểu mới trừ khi có kịch bản thật không biểu diễn được — mỗi kiểu mới là thêm một nhánh phải test và phải giải thích.

### 2.5. Alert tương quan có `_id` tất định

`_id = sha1("<rule_id>|<key>|<bucket>")` với `bucket = floor(window_end / window)`.

Correlator poll mỗi 60s nhưng cửa sổ rule tới 7200s → các lần quét chồng lấn nhau. `_id` tất định làm lần quét sau **ghi đè** lần trước thay vì nhân bản alert. Đây là bất biến, không được đổi.

### 2.6. Custom rule/decoder mount qua `/wazuh-config-mount/`, không mount thẳng vào `/var/ossec/etc`

`/var/ossec/etc` là named volume `wazuh_etc`. Bind-mount một file vào trong đó khiến Docker tạo sẵn cây thư mục → volume bị coi là "đã có dữ liệu" → entrypoint không copy nội dung gốc từ image → mất `etc/shared/ar.conf`, `etc/lists/*` → `wazuh-analysisd` chết với `(1103): Could not open file 'etc/shared/ar.conf'`.

Script `/etc/cont-init.d/0-wazuh-init` chạy `cp -r /wazuh-config-mount/* /var/ossec` lúc khởi động, nên file đặt ở `/wazuh-config-mount/etc/...` được chép đúng vị trí.

### 2.7. Đường vòng ngược qua manager là tuỳ chọn, không bắt buộc

`ManagerSink` bắn alert tương quan vào unix socket của manager để chúng đi qua ruleset (rule 100900–100903) và hưởng active response / email. Mặc định **tắt** (`MANAGER_SOCKET` không set, socket không mount). Bật khi cần demo phản ứng tự động.

---

## 3. Bố cục thư mục

```
SIEM-raw/
├── docker/single-node/        # Tầng hạ tầng
│   ├── docker-compose.yml     #   4 service: manager, indexer, dashboard, correlator
│   ├── generate-certs.yml     #   job sinh chứng chỉ TLS
│   ├── .env                   #   WAZUH_VERSION + credentials  (KHÔNG commit)
│   └── config/
│       ├── certs/             #   private key + cert  (KHÔNG commit)
│       ├── certs.yml          #   khai báo node cho certs-tool
│       ├── wazuh_manager/ossec.conf
│       ├── wazuh_indexer/{wazuh.indexer.yml,internal_users.yml}
│       └── wazuh_dashboard/{opensearch_dashboards.yml,wazuh.yml}
│
├── custom/                    # Tầng phát hiện lớp 2 — nạp vào manager
│   ├── decoders/local_decoder.xml
│   ├── rules/local_rules.xml
│   └── integrations/          #   chỗ dành cho Slack/webhook, hiện rỗng
│
├── correlation/               # Tầng phát hiện lớp 3 — tiến trình riêng
│   ├── siem_correlator/
│   │   ├── config.py          #   Settings.from_env()
│   │   ├── indexer.py         #   REST client OpenSearch
│   │   ├── rules.py           #   nạp + validate YAML
│   │   ├── engine.py          #   YAML → query, sinh Finding
│   │   ├── sinks.py           #   IndexerSink, ManagerSink
│   │   └── __main__.py        #   vòng lặp, tín hiệu, cờ CLI
│   ├── rules/smb_attack_chain.yml
│   ├── tests/test_engine.py
│   ├── Dockerfile
│   └── requirements.txt       #   chỉ requests + PyYAML
│
├── dashboards/                # Tầng trực quan
│   ├── build_dashboard.py     #   sinh saved objects bằng code, không gõ tay JSON
│   └── siem-correlated-dashboard.ndjson   (sinh ra, import thủ công qua UI)
│
├── scripts/
│   ├── deploy.sh              #   triển khai đầu-cuối
│   ├── simulate_attack.py     #   sinh log tấn công giả lập qua syslog UDP
│   └── test_rules.sh          #   kiểm thử decoder/rule bằng wazuh-logtest
│
├── data/sample-logs/erpapp.log
├── docs/
│   ├── adr/                   #   tài liệu này
│   ├── bao-cao-outline.md     #   khung 6 chương, mỗi mục trỏ file dẫn chứng
│   └── so-tay-van-hanh.md     #   quy trình cho người vận hành SMB
├── .claude/skills/            #   5 skill hướng dẫn agent sửa từng tầng
├── README.md
└── osint-user-scanner-siem-integration-plan.md   # ĐỀ XUẤT TƯƠNG LAI, chưa triển khai
```

### Luồng dữ liệu

```
Agent / firewall syslog / ERP syslog
        │
        ▼
Wazuh Manager  ── decoder (custom/decoders) ── rule (custom/rules) ──▶ alert
        │
        │ Filebeat
        ▼
Wazuh Indexer :  wazuh-alerts-*
        │  ▲
   đọc  │  │  ghi  siem-correlated-YYYY.MM.DD
        ▼  │
    Correlator  (poll mỗi POLL_INTERVAL giây)
        │
        └─(tuỳ chọn)─▶ unix socket manager ─▶ rule 100900-903 ─▶ active response
        │
        ▼
Wazuh Dashboard
```

---

## 4. Quy ước bắt buộc

Đây là phần cần tra cứu nhiều nhất khi sửa code.

### 4.1. Dải ID rule Wazuh

| Dải | Dùng cho |
|---|---|
| `100100–100199` | Ứng dụng ERP nội bộ (`erpapp`) |
| `100200–100299` | Thiết bị mạng gửi syslog (firewall/router) |
| `100900–100999` | Tiếp nhận alert tương quan bắn ngược từ correlator |

Thêm nguồn log mới → cấp dải trăm mới, đừng chen vào dải cũ. Rule `level 0` là rule gốc (base) để `if_sid` trỏ tới, không sinh alert.

### 4.2. Trường tĩnh vs trường động của Wazuh

Đây là bẫy hay gặp nhất khi viết decoder.

- **Trường tĩnh (static)**: `srcip`, `dstuser`, `srcuser`, `url`, `status`, `id`, `action`, `data`, `extra_data`… Trong rule phải gọi bằng thẻ riêng (`<status>`, `<srcip>`), **không** dùng được `<field name="...">`. Vi phạm → analysisd báo `Field 'extra_data' is static`.
- **Trường động (dynamic)**: mọi tên khác do mình đặt. Trong rule gọi bằng `<field name="...">`, so sánh bằng biểu thức.

**Quy ước của đồ án**: mọi trường nghiệp vụ riêng đặt tiền tố `erp.` để chắc chắn là trường động. Trên Indexer chúng nằm ở `data.erp.*`.

### 4.3. Tên trường dùng trong rule tương quan

Rule YAML lọc theo tên trường của index `wazuh-alerts-*`:

`rule.id` (chuỗi), `rule.level` (số), `rule.groups` (mảng), `agent.name`, `data.srcip`, `data.dstuser`, `data.srcuser`, `data.status`, `data.url`, `data.erp.*`.

Hậu tố `__gte` / `__lte` / `__gt` / `__lt` dịch thành range query. Giá trị dạng list dịch thành `terms`. Chuỗi chứa `*` hoặc `?` dịch thành `wildcard`.

### 4.4. Index

| Index | Ai ghi | Nội dung |
|---|---|---|
| `wazuh-alerts-*` | Filebeat của manager | Alert lớp 1 + lớp 2 |
| `siem-correlated-YYYY.MM.DD` | Correlator (`IndexerSink`) | Alert lớp 3 |

Template `siem-correlated` được correlator tự tạo lúc khởi động (xem `sinks.py: INDEX_TEMPLATE`).

### 4.5. Biến môi trường của correlator

`INDEXER_URL`, `INDEXER_USERNAME`, `INDEXER_PASSWORD`, `INDEXER_VERIFY_CERTS`, `ALERTS_INDEX`, `OUTPUT_INDEX_PREFIX`, `RULES_PATH`, `POLL_INTERVAL`, `LOOKBACK_SLACK`, `LOG_LEVEL`, `MANAGER_SOCKET`.

### 4.6. Ngôn ngữ

Tài liệu, comment và mô tả rule viết tiếng Việt. File cấu hình XML/YAML dùng tiếng Việt **không dấu** (tránh vấn đề mã hoá khi analysisd đọc). Tên biến, tên hàm, tên trường viết tiếng Anh.

---

## 5. Hệ quả

### 5.1. Tích cực

- Sửa một tầng không đụng tầng khác. Đổi ngưỡng rule không cần build lại correlator; sửa correlator không cần restart manager.
- Correlator chỉ phụ thuộc `requests` + `PyYAML` → dựng lại ở đâu cũng được, dễ giải thích trước hội đồng.
- `_id` tất định làm correlator idempotent → chạy lại `--once` bao nhiêu lần cũng không sinh alert trùng, thuận lợi khi demo.
- `build_dashboard.py` sinh dashboard bằng code → sửa dashboard là sửa Python, review được, không phải gõ tay JSON.
- Có `--dry-run` và `--once` → kiểm chứng rule mà không làm bẩn index.

### 5.2. Tiêu cực (chấp nhận có ý thức)

- **Không realtime**: độ trễ phát hiện của lớp 3 tối đa bằng `POLL_INTERVAL` (60s). Đổi lại là kiến trúc đơn giản, không cần message broker.
- **Query lặp**: mỗi chu kỳ query lại toàn bộ cửa sổ của mọi rule. Rule cửa sổ 2 giờ bị query 120 lần trên cùng khoảng thời gian. Chấp nhận được ở quy mô SMB, phải nêu số liệu ở chương đánh giá hiệu năng.
- **Một node, không HA**: `number_of_replicas: 0`. Máy chủ chết là mất giám sát và có thể mất dữ liệu.
- **`MAX_BUCKETS = 500` cứng**: quá 500 khoá trong một cửa sổ sẽ mất khoá âm thầm, không cảnh báo.

---

## 6. Khoảng trống đã biết (chưa sửa tại thời điểm viết ADR)

Ghi lại để phiên sau không phải phát hiện lại.

| # | Vấn đề | Vị trí | Mức |
|---|---|---|---|
| 1 | `.env` chứa credentials mặc định nhưng **không** nằm trong `.gitignore` (`.gitignore` chỉ chặn `config/certs/`). Repo hiện chưa `git init`; nếu init thì credentials vào lịch sử ngay | `docker/single-node/.env`, `.gitignore` | Cao |
| 2 | Điều kiện thứ tự của `sequence` quá lỏng: `first[i] <= last[i+1]` cho phép giai đoạn sau bắt đầu **trước** giai đoạn trước mà vẫn khớp → false positive. Chặt hơn: `first[i] <= first[i+1]` | `correlation/siem_correlator/engine.py`, `_run_sequence` | Cao |
| 3 | Không có ISM policy / retention. `wazuh-alerts-*` và `siem-correlated-*` mọc vô hạn. Outline chương 3.3 có mục "vòng đời dữ liệu" nhưng code chưa hiện thực | Indexer | Cao |
| 4 | `INDEXER_VERIFY_CERTS=false` cho correlator, trong khi manager dùng `FILEBEAT_SSL_VERIFICATION_MODE: full`. Đã có root-ca thì nên mount vào correlator và bật verify | `docker-compose.yml` | Trung bình |
| 5 | `<auth><use_password>no</use_password>` — ai tới được cổng 1515 đều enroll agent được. Chấp nhận trong lab, phải ghi rõ là hạn chế trong báo cáo | `ossec.conf` | Trung bình |
| 6 | `lookback_slack` khai báo trong `Settings` nhưng không nơi nào dùng — dead config | `config.py` | Thấp |
| 7 | `MANAGER_SOCKET` chưa set và socket chưa mount → `ManagerSink` và rule 100900–903 **hiện không chạy**, active response cho alert tương quan chưa được kiểm chứng | `docker-compose.yml` | Trung bình |
| 8 | Dashboard phải import thủ công qua UI, `deploy.sh` không tự làm | `scripts/deploy.sh` | Thấp |
| 9 | `test_rules.sh` hardcode tên container `siem-raw-wazuh.manager-1` | `scripts/test_rules.sh` | Thấp |
| 10 | Test chỉ phủ `engine.py`; `rules.py`, `sinks.py`, `indexer.py` chưa có test. Không có CI, không lint | `correlation/tests/` | Thấp |
| 11 | `osint-user-scanner-siem-integration-plan.md` (1507 dòng) mô tả kiến trúc Kafka + OCSF + worker riêng, **không khớp** kiến trúc hiện tại. Nằm ở thư mục gốc ngang hàng README nên dễ bị hiểu nhầm là đã làm | thư mục gốc | Trung bình |

Về mục 11: với đồ án một người, dựng Kafka + OCSF là rủi ro phình phạm vi lớn hơn giá trị mang lại. Khuyến nghị giữ ở mức "hướng phát triển" (mục 6.3 của outline), không triển khai trước khi bảo vệ.

---

## 7. Sửa ở đâu — bảng tra nhanh

| Muốn làm gì | Sửa file nào | Kiểm chứng bằng |
|---|---|---|
| Bắt một loại log ứng dụng mới | `custom/decoders/local_decoder.xml` rồi `custom/rules/local_rules.xml` | `bash scripts/test_rules.sh` |
| Đổi ngưỡng brute force / port scan | `custom/rules/local_rules.xml` (`frequency`, `timeframe`) | `scripts/simulate_attack.py --scenario bruteforce` |
| Thêm chuỗi tấn công nhiều bước | `correlation/rules/smb_attack_chain.yml` | `python -m siem_correlator --once --dry-run` |
| Thêm kiểu rule tương quan mới | `correlation/siem_correlator/rules.py` (`VALID_TYPES`, validate) + `engine.py` (runner) + test | `correlation/tests/test_engine.py` |
| Đổi cấu hình thu thập log | `docker/single-node/config/wazuh_manager/ossec.conf` | `docker compose restart wazuh.manager` rồi xem `ossec.log` |
| Thêm/sửa biểu đồ | `dashboards/build_dashboard.py` | chạy script rồi import lại NDJSON |
| Đổi kịch bản demo | `scripts/simulate_attack.py` | `--print-only` |
| Bật active response cho alert tương quan | mount socket manager + set `MANAGER_SOCKET` trong `docker-compose.yml` | xem alert level 10/12/14 nhóm `correlation` |

---

## 8. Cách dùng ADR này ở các phiên sau

Mở đầu phiên bằng một trong các dạng:

- "Đọc `docs/adr/0001-kien-truc-tong-the.md` rồi làm X" — tránh phải mô tả lại toàn bộ cấu trúc.
- "Theo mục 4.2 của ADR-0001, viết decoder cho log <nguồn mới>" — dẫn thẳng quy ước cần áp dụng.
- "Sửa khoảng trống số N ở mục 6 của ADR-0001" — dẫn thẳng việc cần làm.

Khi một quyết định trong ADR này thay đổi: **không sửa đè** mục 2. Tạo ADR mới (`0002-...`) nêu rõ nó thay thế quyết định nào, rồi đánh dấu quyết định cũ là "Đã thay thế bởi ADR-000N". Riêng mục 3, 4, 6, 7 là phần mô tả hiện trạng — cập nhật tại chỗ khi code đổi.

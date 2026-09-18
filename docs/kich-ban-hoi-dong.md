# Kịch bản chạy script cho từng tình huống hội đồng

Bảng tra nhanh. Nội dung trả lời từng câu: [docs/bao-ve-hoi-dong.md](bao-ve-hoi-dong.md).

| Tình huống / câu hỏi | Script | Mục đích |
|---|---|---|
| A — Bão alert | `scripts/benign_traffic.py --storm` | Chứng minh rule tương quan **không** nổ 200 lần |
| B — Kẻ tấn công biết ngưỡng | `scripts/evade_thresholds.py` | So sánh né ngưỡng với chạy trên ngưỡng |
| C — Nội gián im lặng | `scripts/slow_insider.py` | Chứng minh hệ thống mù với hành vi 60 ngày |
| D — Dashboard trống lúc demo | `scripts/troubleshoot_demo.sh` | Chẩn đoán 5 bước tự động |
| E — Giám đốc hỏi tiền | `scripts/measure_capacity.sh` | Đo EPS, dung lượng, ngoại suy |
| F — Rule sai hướng (`^OK$`) | `scripts/negative_rule_test.sh` | Kiểm thử **âm tính** tự động |
| G — Mở rộng 40 → 400 | `scripts/measure_capacity.sh` | Chỉ ra nút thắt theo thứ tự |
| Câu 13 — Precision / F1 | `scripts/eval_detection.py` | Bộ chỉ số đầy đủ |

---

## Chuẩn bị

Stack phải đang chạy:

```bash
bash scripts/deploy.sh
```

Kiểm tra nhanh:

```bash
docker compose -f docker/single-node/docker-compose.yml ps
```

Script Python cần `requests`:

```bash
pip install requests
```

---

## Tình huống A — Bão alert

```bash
python scripts/benign_traffic.py --storm --employees 200 --delay 0.2
```

Đợi hơn 60 giây rồi đếm:

```bash
python scripts/eval_detection.py --fp-window 'now-15m' 'now'
```

**Kết quả cần thấy:** 400 alert Wazuh thô (100110 + 100111), **0 alert tương quan**.

**Câu nói khi trình bày:** rule tương quan xây trên **alert đã tổng hợp** (100120/100121), không
trên sự kiện thô (100111) — nên bão sự kiện thô không thành bão alert tương quan.

---

## Tình huống B — Kẻ tấn công biết ngưỡng

Chạy hai lần, so kết quả. **Không chạy song song** — sẽ lẫn dữ liệu.

```bash
python scripts/evade_thresholds.py --mode loud
```

```bash
python scripts/evade_thresholds.py --mode evade
```

Chế độ `evade` mất ~11 phút — chậm **có chủ ý**, đó chính là cách né. Xem trước không mất thời gian:

```bash
python scripts/evade_thresholds.py --mode evade --print-only --compress 0.01
```

> Cảnh báo: `--compress` làm mất hiệu lực của việc né ngưỡng. Chỉ dùng để xem trước luồng sự kiện,
> không dùng để kết luận.

**Bảng đưa hội đồng:** số alert của `loud` so với `evade`, cùng một mục tiêu, cùng lượng dữ liệu
lấy ra.

---

## Tình huống C — Nội gián im lặng

```bash
python scripts/slow_insider.py --inject
```

Đợi một chu kỳ quét (60 giây), rồi:

```bash
python scripts/slow_insider.py --analyze
```

Dọn sạch sau khi demo xong:

```bash
python scripts/slow_insider.py --cleanup
```

**Lưu ý phải nói rõ với hội đồng:** script này ghi thẳng document vào Indexer, không đi qua syslog.
Lý do: `@timestamp` của alert Wazuh là thời điểm **manager sinh alert**, không phải thời điểm trong
dòng log — nên không thể tái hiện hành vi trải 60 ngày bằng cách gửi syslog. Đây là **bộ gá kiểm
thử**, không phải đường đi thật của dữ liệu. Mọi document tiêm vào mang cờ `_synthetic: true` và
nằm trong index riêng `wazuh-alerts-4.x-synthetic-insider`.

---

## Tình huống D — Dashboard trống lúc demo

```bash
bash scripts/troubleshoot_demo.sh
```

Chạy 5 bước từ rẻ đến đắt, mỗi bước in kết luận và việc cần làm. **Chạy thử trước buổi bảo vệ ít
nhất một lần** để quen với output — lúc đứng trước hội đồng thì không còn thời gian đọc kỹ.

---

## Tình huống E và G — Đo năng lực

Đo trên hệ thống đang chạy:

```bash
bash scripts/measure_capacity.sh
```

Ngoại suy cho 50 endpoint, lưu 90 ngày:

```bash
bash scripts/measure_capacity.sh --endpoints 50 --retention 90
```

Muốn số đo có nghĩa thì phải có tải. Sinh tải nền trước:

```bash
python scripts/benign_traffic.py --profile office --duration 600 --delay 0.2
```

**Cách trình bày đúng:** đưa **phương pháp đo** và số đo được trên lab, kèm hệ số ngoại suy và ba lý
do khiến ngoại suy có thể sai (script tự in ra). Không trình bày con số ngoại suy như kết quả.

---

## Tình huống F — Kiểm thử âm tính

```bash
bash scripts/negative_rule_test.sh
```

Thoát mã 1 nếu có ca sai — cắm được vào CI. Khác `scripts/test_rules.sh` ở chỗ: kỳ vọng là **dữ
liệu được so tự động**, không phải comment đọc bằng mắt.

Bốn nhóm ca:

1. Trạng thái đăng nhập phải neo `^OK$` / `^FAILED$` — lỗi đã vấp.
2. Ngưỡng 10000 dòng phải so bằng số, không đếm chữ số.
3. Dòng log hỏng phải rơi vào 100101, không được biến mất.
4. Cấp quyền admin phải tách khỏi quyền thường.

**Câu nói khi trình bày:** bộ ca này phủ 4 nhóm lỗi **đã biết**. Nó không chứng minh không còn lỗi
cùng loại — chỉ chứng minh 4 lỗi đã vấp sẽ không quay lại. Mỗi khi phát hiện lỗi mới, thêm một ca.

---

## Câu 13 — Bộ chỉ số đầy đủ

**Bước 1 — đo false positive.** Chạy lưu lượng lành tính, càng lâu càng có giá trị:

```bash
python scripts/benign_traffic.py --profile both --duration 3600 --delay 1.0
```

Script in ra khoảng thời gian và lệnh đếm tương ứng ở cuối. Dán lệnh đó chạy:

```bash
python scripts/eval_detection.py --fp-window '2026-09-09T14:00:00' '2026-09-09T15:00:00'
```

**Bước 2 — đo recall.** Chạy khi **không** có lưu lượng lành tính chạy nền:

```bash
python scripts/eval_detection.py --recall --delay 0.3
```

Mỗi kịch bản đợi `POLL_INTERVAL + 15` giây, 5 kịch bản mất khoảng 6–7 phút.

**Bước 3 — tổng hợp.** Điền số từ hai bước trên:

```bash
python scripts/eval_detection.py --report --tp 7 --fn 0 --fp 3 --hours 1 --endpoints 1
```

**Chỉ số quan trọng nhất là FP/ngày**, không phải F1. Một SME 50 máy chịu được vài alert mỗi ngày.
Recall 100% mà 200 alert/ngày thì hệ thống vô dụng vì không ai đọc hết.

---

## Thứ tự chạy khi diễn tập trước buổi bảo vệ

Một buổi diễn tập đầy đủ, khoảng 2 giờ:

```bash
bash scripts/deploy.sh                                          # 1. dựng stack
bash scripts/negative_rule_test.sh                              # 2. rule còn đúng không
python scripts/benign_traffic.py --profile both --duration 1800 # 3. đo FP (30 phút)
python scripts/eval_detection.py --fp-window '<bắt đầu>' '<kết thúc>'
python scripts/eval_detection.py --recall --delay 0.3           # 4. đo Recall (~7 phút)
python scripts/eval_detection.py --report --tp .. --fn .. --fp .. --hours 0.5 --endpoints 1
bash scripts/measure_capacity.sh --endpoints 50 --retention 90  # 5. số liệu dung lượng
python scripts/slow_insider.py --inject                         # 6. tình huống C
python scripts/slow_insider.py --analyze
python scripts/slow_insider.py --cleanup
bash scripts/troubleshoot_demo.sh                               # 7. tập chẩn đoán
```

Ghi lại toàn bộ số liệu — đó là nội dung chương "Kiểm thử và đánh giá".

---

## Trước khi vào phòng bảo vệ

- [ ] Chạy `bash scripts/troubleshoot_demo.sh` một lần, xác nhận mọi bước `[OK]`.
- [ ] Chạy `bash scripts/negative_rule_test.sh`, xác nhận không có ca `FAIL`.
- [ ] Dọn dữ liệu tổng hợp: `python scripts/slow_insider.py --cleanup`.
- [ ] Đặt bộ lọc thời gian của dashboard về `Last 15 minutes`.
- [ ] Chuẩn bị sẵn con số FP/ngày và Recall — đây là hai con số hội đồng sẽ hỏi.
- [ ] Nhớ: `--delay` phải ≤ 1.0, nếu không rule tần suất của Wazuh không nổ.

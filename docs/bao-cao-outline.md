# Đề cương báo cáo đồ án

> Khung chương phù hợp với sản phẩm thực tế trong repo. Mỗi mục ghi kèm nguồn dẫn chứng lấy từ code/cấu hình để tránh viết chay.

## Mở đầu
- Lý do chọn đề tài: SMB Việt Nam thiếu năng lực giám sát, không đủ ngân sách cho SIEM thương mại.
- Mục tiêu: dựng được hệ thống giám sát chạy thật, chi phí phần mềm bằng 0, một người vận hành được.
- Phạm vi: một node, giám sát endpoint + thiết bị mạng + một ứng dụng nội bộ. Không bao gồm SOAR đầy đủ, không bao gồm HA.
- Phương pháp: khảo sát → thiết kế → triển khai lab → kiểm thử bằng kịch bản tấn công giả lập → đánh giá.

## Chương 1 — Cơ sở lý thuyết
1.1 Khái niệm SIEM, các thành phần: thu thập, chuẩn hoá, tương quan, cảnh báo, lưu trữ.
1.2 Vòng đời log: sinh → thu → phân tích → lưu → xoá.
1.3 Phân biệt log management, SIEM, XDR, SOAR.
1.4 MITRE ATT&CK và vai trò trong ánh xạ rule (dẫn `mitre` trong `custom/rules/local_rules.xml` và `correlation/rules/*.yml`).
1.5 Đặc thù SMB: nhân sự CNTT kiêm nhiệm, hạ tầng nhỏ, ngân sách hạn chế → tiêu chí chọn giải pháp.

## Chương 2 — Khảo sát và lựa chọn giải pháp
2.1 Hiện trạng doanh nghiệp mẫu: sơ đồ mạng, danh sách tài sản, nguồn log sẵn có.
2.2 So sánh: Wazuh, Graylog, ELK thuần, Security Onion, Splunk Free — theo tiêu chí chi phí, tài nguyên, độ khó vận hành, tính năng agent, cộng đồng.
2.3 Kết luận chọn Wazuh + lý do.
2.4 Xác định rủi ro ưu tiên giám sát: chiếm tài khoản, mã độc/ransomware, rò rỉ dữ liệu khách hàng, gian lận nội bộ, thiết bị mạng bị dò quét.

## Chương 3 — Phân tích và thiết kế
3.1 Kiến trúc tổng thể (sơ đồ trong `README.md` mục 1).
3.2 Thiết kế thu thập log: agent, syslog, ứng dụng nội bộ.
3.3 Thiết kế lưu trữ: index, vòng đời dữ liệu, ước lượng dung lượng theo EPS.
3.4 Thiết kế phát hiện ba lớp: rule có sẵn / rule tự viết / correlation.
3.5 Thiết kế decoder cho log ứng dụng nội bộ: định dạng log, các trường bóc tách.
3.6 Thiết kế engine tương quan: ba kiểu rule `threshold`, `distinct`, `sequence`; cơ chế `_id` tất định để chống nhân bản alert.
3.7 Thiết kế dashboard và quy trình xử lý sự cố.

## Chương 4 — Triển khai
4.1 Chuẩn bị hạ tầng, yêu cầu tài nguyên, `vm.max_map_count`.
4.2 Triển khai stack bằng Docker Compose (`docker/single-node/`), sinh chứng chỉ TLS.
4.3 Cấu hình manager: remote, auth, syscheck, sca, vulnerability-detection, active response (`config/wazuh_manager/ossec.conf`).
4.4 Cài agent lên máy trạm Windows/Linux; cấu hình syslog cho thiết bị mạng.
4.5 Viết decoder và rule (`custom/`), kiểm thử bằng `wazuh-logtest`.
4.6 Viết engine tương quan (`correlation/`): cấu trúc module, luồng xử lý, cách dịch rule YAML thành query.
4.7 Xây dashboard (`dashboards/build_dashboard.py`).

## Chương 5 — Kiểm thử và đánh giá
5.1 Kịch bản kiểm thử: brute force, password spraying, rò rỉ dữ liệu, leo thang đặc quyền, quét cổng, chuỗi chiếm tài khoản đầy đủ (`scripts/simulate_attack.py`).
5.2 Kết quả: bảng đối chiếu kịch bản ↔ rule kích hoạt ↔ độ trễ phát hiện. Kèm ảnh chụp dashboard.
5.3 Unit test engine tương quan (`correlation/tests/test_engine.py`).
5.4 Đánh giá hiệu năng: EPS chịu được, RAM/CPU/dung lượng đĩa tiêu thụ.
5.5 Đánh giá false positive và cách tinh chỉnh ngưỡng.
5.6 So sánh trước/sau khi có lớp correlation: những chuỗi tấn công mà rule đơn lẻ bỏ sót.

## Chương 6 — Kết luận
6.1 Kết quả đạt được so với mục tiêu.
6.2 Hạn chế: một node không HA, correlation chạy theo chu kỳ chứ không realtime, chưa tích hợp threat intelligence.
6.3 Hướng phát triển: cluster nhiều node, làm giàu dữ liệu bằng threat intel, tự động phản ứng (SOAR), gom log cloud.

## Phụ lục
- A. Toàn văn `ossec.conf`.
- B. Decoder và rule tự viết.
- C. Rule tương quan YAML.
- D. Sổ tay vận hành (`docs/so-tay-van-hanh.md`).
- E. Log mẫu và kết quả `wazuh-logtest`.

---

## Việc cần làm để hoàn thiện báo cáo

- [ ] Vẽ sơ đồ mạng doanh nghiệp mẫu (draw.io) → xuất PNG vào `docs/img/`
- [ ] Chụp màn hình dashboard sau khi chạy kịch bản demo
- [ ] Đo thực tế EPS và tài nguyên tiêu thụ, ghi số liệu vào chương 5
- [ ] Bảng đối chiếu rule ↔ kỹ thuật MITRE ATT&CK
- [ ] Ước lượng chi phí triển khai (phần cứng, điện, nhân công) so với SIEM thương mại
- [ ] Slide bảo vệ (làm sau khi báo cáo chốt)

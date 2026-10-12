# Compliance mapping — checkpoint 5

**Phạm vi:** map control kỹ thuật của lab tới **chủ đề nghĩa vụ** trong các văn bản. Mình **chưa đối chiếu văn bản gốc** (công báo/cổng văn bản pháp luật) nên **không trích số điều/khoản**; cột "Điều khoản" ghi `chưa xác minh`. Lab chạy trên dữ liệu synthetic với `--mock`, principal là fixture mô phỏng; bảng này cho thấy control tồn tại và có bằng chứng, **không** chứng minh hệ thống tuân thủ pháp luật.

Số dòng code tham chiếu commit nộp bài. `reports/ledger.jsonl` được sinh ở checkpoint 5: dòng 1–23 là run `--as dpo`, dòng 24–46 là run `--as support_l1`.

## Luật 91/2025/QH15 (Bảo vệ dữ liệu cá nhân)

| Chủ đề nghĩa vụ | Điều khoản | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|---|
| Xử lý đúng mục đích, giới hạn mục đích | chưa xác minh | Policy deny khi `request_purpose` không thuộc `purposes` của principal | `agent/policy.py:94`; `data/principals.json:2-4` | Purpose do runner gán cứng (`summarize-tickets`, `support-reply`), không lấy từ yêu cầu thật của người dùng |
| Tối thiểu hoá dữ liệu, chỉ người có thẩm quyền được truy cập | chưa xác minh | OBO: quyền hiệu lực = `allowed_tools ∩ agent_scopes (∩ parent_scopes)`; `support_l1` không đọc được hồ sơ có CCCD/STK | `agent/policy.py:104-111`; `agent/runner.py:189-195`; `reports/ledger.jsonl:26` (deny `read_customer`, `on_behalf_of: support_l1`) | `--as` là principal mô phỏng, không có xác thực danh tính thật |
| Biện pháp bảo vệ dữ liệu nhạy cảm (CCCD, số tài khoản) | chưa xác minh | PII gate redact CCCD/SĐT/STK/email trước khi text vào context | `agent/pii.py:38-48,61-65`; `agent/runner.py:168`; `tests/test_pii.py` (P = R = 1.000 trên 118 entity) | Regex chỉ đo trên test set synthetic 120 dòng; chưa có NER cho tên người |
| Ngăn chuyển dữ liệu trái phép ra ngoài | chưa xác minh | Rule tối thiểu restricted + egress → deny, đặt trước mọi rule khác | `agent/policy.py:79-81`; `reports/ledger.jsonl:2,25`; `reports/attack-after.log` (0 byte) so với `reports/attack-before.log` | Egress trong lab chỉ là `127.0.0.1:10024`; chưa có DLP ở tầng mạng |
| Ghi nhận, chứng minh hoạt động xử lý | chưa xác minh | Ledger ghi cả allow và deny, có reason, `on_behalf_of`, `run_id`, hash chain | `agent/runner.py:120-134`; `agent/ledger.py:57-88`; `reports/ledger.jsonl` (`verify() = True`) | Hash chain không phát hiện cắt đuôi hoặc viết lại cả file khi không có mốc tin cậy bên ngoài |

## NĐ 356/2025/NĐ-CP (văn bản hướng dẫn về bảo vệ dữ liệu cá nhân)

| Chủ đề nghĩa vụ | Điều khoản | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|---|
| Đánh giá tác động xử lý dữ liệu cá nhân | chưa xác minh | DPIA-lite cho luồng ticket → hồ sơ khách | `reports/dpia-lite.md` | Bản rút gọn cho lab, không theo mẫu biểu chính thức |
| Biện pháp kỹ thuật: kiểm soát truy cập, nhật ký | chưa xác minh | PEP trước mọi tool call; ledger tamper-evident | `agent/runner.py:103-137`; `agent/ledger.py:71-88` | Ledger nằm trong cùng file system với agent, chưa đẩy ra kho log độc lập |
| Xử lý sự cố lộ lọt | chưa xác minh | Incident note cho token giả: phát hiện bằng Gitleaks, ưu tiên thu hồi/rotate | `reports/secrets-incident.md:7,28-36` | Token là synthetic; không có quy trình thông báo cơ quan chức năng trong lab |

## Luật 134/2025/QH15 (Trí tuệ nhân tạo)

| Chủ đề nghĩa vụ | Điều khoản | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|---|
| Con người kiểm soát, quy trách nhiệm cho hành động của hệ thống AI | chưa xác minh | Mỗi tool call gắn principal ra lệnh (`on_behalf_of`), `agent_id`, `run_id`, `expires_at` (TTL 5 phút) | `agent/runner.py:77,121-134,205-206`; `reports/ledger.jsonl` (mọi dòng) | Không có bước con người phê duyệt từng hành động |
| An toàn, chống thao túng hệ thống AI | chưa xác minh | Trifecta split: chỉ dữ liệu typed `list[int]` đi từ Run A sang Run B; Run B không đọc free text | `agent/runner.py:140-154,184-187`; `tests/test_split.py` (không đọc `KH-000777`) | Mock LLM xác định; model thật có thể có hành vi khác ngoài bộ marker |
| Minh bạch, lưu vết | chưa xác minh | Ledger và `injection-corpus.md` ghi trước/sau cho 4 kỹ thuật injection | `injection-corpus.md`; `reports/ledger.jsonl` | Chưa có cơ chế công bố cho người dùng cuối |

## OWASP Top 10 for Agentic Applications

Tên mục theo bản 2026 của OWASP GenAI Security Project.

| Mục | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| **ASI01 — Agent Goal Hijack** (prompt injection gián tiếp qua ticket) | 4 lure khác kỹ thuật; split ngăn free text quyết định khách nào bị đọc; PEP chặn egress | `corpus/ticket-901.md` … `ticket-904b.md`; `agent/runner.py:170-180`; `tests/test_injection.py` (8/8 pass); `reports/attack-before.log` so với `reports/attack-after.log` | Phát hiện injection vẫn dựa trên marker của mock; containment không phụ thuộc phần phát hiện này |
| **ASI03 — Identity & Privilege Abuse** | OBO: principal từ nguồn tin cậy, giao scope theo tầng, agent con không vượt `parent_scopes`, TTL, unknown principal → deny | `agent/policy.py:85-111`; `agent/runner.py:80-82,193`; `tests/test_obo.py` (5/5 pass); `reports/ledger.jsonl:26` | Danh tính mô phỏng bằng `--as`, chưa có token ký số hoặc OAuth token exchange |
| **ASI04 — Agentic Supply Chain Vulnerabilities** | Gitleaks v8.30.1 quét lịch sử; hook pre-commit pin `rev: v8.30.1`; `requirements.lock` có hash, cài bằng `--require-hashes` | `.pre-commit-config.yaml:6-11`; `requirements.lock`; `reports/secrets-incident.md:11-17`; `tests/test_supply_chain.py` (3/3 pass) | Chưa ký/kiểm SBOM; hook chỉ chặn commit tương lai trên máy có cài hook |

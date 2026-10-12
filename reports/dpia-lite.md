# DPIA-lite — checkpoint 5

Hệ thống: agent hỗ trợ khách hàng Day 24 (`agent/`), chạy `--mock` trên dữ liệu **synthetic**. Đây là bản đánh giá rút gọn cho lab, không theo mẫu biểu chính thức của cơ quan quản lý.

## 1. Loại dữ liệu và phân loại

| Nguồn | Nội dung | Phân loại trong policy | Ghi chú |
|---|---|---|---|
| `corpus/ticket-*.md` | Nội dung ticket hỗ trợ; có thể chứa tên, mã khách và chỉ thị do attacker cài | `internal`, **không tin cậy** | Bề mặt tấn công prompt injection (ticket 901–904b) |
| `data/customers.json` | Họ tên, **CCCD**, **SĐT**, **số tài khoản ngân hàng**, email, `related_tickets` | `restricted` | CCCD và số tài khoản là dữ liệu nhạy cảm, gây hại lớn nếu lộ |
| `data/principals.json` | Vai trò, tool và purpose được phép | cấu hình tin cậy | Fixture mô phỏng, không phải hệ thống định danh |
| `reports/ledger.jsonl` | Metadata của tool call: principal, run, tool, decision, reason, `args_hash` | `internal` | Không chứa PII thô: đã kiểm bằng grep CCCD/STK/SĐT của `KH-000999`, không có kết quả |

## 2. Mục đích xử lý và principal

| Principal | Tool được phép | Purpose được phép | Có đọc hồ sơ khách? |
|---|---|---|---|
| `support_l1` | `search_docs` | `summarize-tickets`, `support-reply` | **Không** (deny ở PEP, trước khi đọc) |
| `billing` | `search_docs`, `read_customer` | `summarize-tickets`, `billing-reconciliation` | Có, chỉ với purpose đối soát |
| `dpo` | `search_docs`, `read_customer` | `summarize-tickets`, `support-reply`, `privacy-audit` | Có, chỉ khách gắn với ticket qua `related_tickets` |

Runner gán purpose `summarize-tickets` cho Run A và `support-reply` cho Run B. Không principal nào có `http_post`.

## 3. Dữ liệu đi qua những run/tool nào, endpoint nào

```
Người dùng (--as <principal>)
  │ query
  ▼
Run A  [scope: search_docs, depth 0]
  search_docs(corpus/) ──► pii.redact() ──► summarize (output CLI)
  │                    └─► find_injection → yêu cầu http_post ──► PEP: DENY (restricted + egress)
  │ chỉ list[int] ticket id lấy từ TÊN FILE
  ▼
Run B  [scope: read_customer, depth 1, parent: search_docs+read_customer]
  ticket id ─► related_tickets (customers.json) ─► read_customer ──► PEP: allow (dpo) / deny (support_l1)
  Hồ sơ chỉ ở trong phiên, không đi ra output hay egress.

Endpoint egress duy nhất có thể có: http://127.0.0.1:10024 (sink lab). Trong bài nộp không có lần POST nào.
```

## 4. Rủi ro, biện pháp và bằng chứng

| Rủi ro | Trước containment | Biện pháp | Sau containment |
|---|---|---|---|
| Injection trong ticket khiến agent gửi hồ sơ ra ngoài | `reports/attack-before.log`: POST `/reconcile` chứa CCCD/STK synthetic của `KH-000999`, kể cả dưới `support_l1` | PEP: restricted + egress → deny | `reports/attack-after.log` 0 byte; `reports/ledger.jsonl:2` (dpo), `:25` (support_l1) deny `http_post` |
| Attacker nêu ID khách bất kỳ để agent đọc | Baseline đọc mọi `KH-xxxxxx` trong text | Trifecta split: Run B chỉ suy khách từ `related_tickets` | `tests/test_split.py`: `KH-000777` không bao giờ bị đọc |
| Nhân viên L1 xem CCCD/STK | Baseline bỏ qua `--as` | OBO tại tool boundary | `reports/ledger.jsonl:26`: deny `read_customer` cho `support_l1` |
| Sửa log để che dấu vết | Không có log phía agent | Hash chain + reason bắt buộc | `verify()` = True; sửa 1 dòng giữa file → False |
| Secret lộ qua lịch sử Git | Token giả ở `1bdd849` | Gitleaks, hook pin, thu hồi/rotate | `reports/secrets-incident.md` |

**Rủi ro còn lại được chấp nhận:** `dpo` vẫn đọc hợp lệ hồ sơ `KH-000999`, vì khách này gắn với ticket 901–905, kể cả khi ticket là lure. Lúc đó chỉ PEP egress ngăn dữ liệu ra ngoài. Nếu policy egress bị cấu hình sai, đây là điểm lộ duy nhất.

## 5. Giới hạn của mock và của bài lab

- `--mock` là LLM xác định, "tuân theo" chỉ thị khi thấy từ 2 marker trở lên. Model thật có thể bị thao túng bằng câu chữ khác; containment (split + PEP) không phụ thuộc phần phát hiện, nhưng chưa được thử với model thật.
- `--as` chỉ chọn principal mô phỏng, **không phải xác thực**. Hệ thống thật cần định danh có ký số (ví dụ OAuth token exchange) và kiểm `expires_at` từ token, không từ runner.
- PII gate là regex, đo trên 120 câu synthetic; chưa nhận diện tên người, địa chỉ hay định dạng lạ.
- Ledger là file JSONL cục bộ: hash chain phát hiện sửa dòng giữa file, **không** phát hiện cắt đuôi hoặc viết lại toàn bộ chuỗi nếu thiếu mốc tin cậy bên ngoài.
- Không có retention, xoá dữ liệu theo yêu cầu chủ thể hay đồng ý (consent) trong phạm vi lab.
- Đánh giá này chưa đối chiếu điều khoản pháp luật cụ thể (xem `reports/compliance-mapping.md`).

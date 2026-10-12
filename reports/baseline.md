# Baseline — checkpoint 1

Đối tượng đọc: `_naive_loop()` trong `agent/loop.py` (đường chạy khi `agent/runner.py` còn là stub `RunnerScaffoldPending`, xem `run_once()` dòng 67–74).

1. **Agent có identity mỗi run chưa?** Chưa. `_naive_loop(message, llm)` (`agent/loop.py:27`) chỉ nhận message và llm, không tạo `run_id`/`agent_id`, không có `expires_at`. `principal_id` từ `--as` được `run_once()` nhận (`agent/loop.py:58`) nhưng **không được truyền** vào `_naive_loop` (`agent/loop.py:74`), nên chạy `--as support_l1` vẫn đọc được `read_customer` — mọi run dùng chung một quyền ngầm định, không phân biệt ai ra lệnh.

2. **Ai cho phép `http_post`?** Không ai. Quyết định gọi tool đến từ chính nội dung tài liệu không tin cậy: `tools.search_docs()` (`agent/loop.py:31`) đưa toàn văn ticket vào, `llm.find_injection()` (`agent/loop.py:34`, `agent/llm.py:65`) trích `customer_ids` và `target_url` từ text attacker, rồi loop gọi thẳng `tools.read_customer()` (`agent/loop.py:39`) và `tools.http_post(injected.target_url, ...)` (`agent/loop.py:44`). Không có PEP/policy check trước tool call. Thứ duy nhất giới hạn là allowlist cứng `127.0.0.1:10024` trong `agent/tools.py:26-27,76-78` — đó là rào an toàn cho lab, không phải authorization: nó không xét classification, purpose hay principal.

3. **Nếu gửi sai PII ra sink, bằng chứng ở đâu?** Phía agent không có bằng chứng nào: `_naive_loop` không ghi ledger, không log tool call, không ghi allow/deny hay reason; CLI chỉ in `llm.summarize(docs)` (`agent/loop.py:54`) nên người dùng không thấy gì bất thường. Bằng chứng duy nhất nằm ở **phía nhận**: `sink/sink.py` `do_POST()` ghi body vào `reports/sink.log` (`sink/sink.py:42-47`). Chạy thử `python -m agent.loop --mock --as support_l1 "Tóm tắt ticket về hoá đơn"` thì sink.log nhận một POST `/reconcile` chứa record synthetic `KH-000999` (cccd, phone, bank_account, email) — tức là chỉ phát hiện được nhờ đích exfil, không phải nhờ hệ thống tự audit.

**Ba lớp còn thiếu** (sẽ thêm ở checkpoint 3): identity/OBO theo run (`agent/policy.py`, `agent/runner.py`), PEP trước mọi tool call (`agent/policy.py:check`), ledger hash chain cho cả allow và deny (`agent/ledger.py`).

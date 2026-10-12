# Verification

Chạy ngày 2026-10-12, trên máy cá nhân.

- **OS / Python / Gitleaks version:** Windows 11 Pro (10.0.26300), **Windows native** qua Git Bash/PowerShell vì máy không có WSL Ubuntu; Python 3.12.6 trong `.venv`; Gitleaks **8.30.1** (binary `windows_x64` từ release chính thức, SHA256 khớp file checksums); pre-commit 4.6.2.

- **`python -m pytest tests/ -q`:** `33 passed`. Gồm `test_pii` 2, `test_policy` 4, `test_obo` 5, `test_split` 1, `test_ledger` 3, `test_injection` 8 (4 biến thể × `support_l1`/`dpo`), `test_supply_chain` 3, `test_check_lure_cli` 3, `test_scaffold_dispatch` 4. PII: `gold=118 pred=118 tp=118`, precision = recall = 1.000.

- **`pre-commit run --all-files`:** `Detect hardcoded secrets ... Passed` (hook `gitleaks-system`, `rev: v8.30.1`). Hook dùng `--staged` nên khi không có gì được stage thì quét 0 byte. Đã thử stage một file chứa token giả `LAB24-DEMO`: hook **Failed** với `RuleID: lab24-synthetic-token`; file thử đã gỡ khỏi stage và xoá, không commit.

- **Gitleaks:**
  - `gitleaks git --config .gitleaks.toml --redact --verbose .` → `leaks found: 1` ở `1bdd849`, `lab-fake-secret.txt`, rule `lab24-synthetic-token`, exit 1. Đúng dự kiến: đây là token giả cài sẵn, không phải secret thật.
  - `gitleaks dir --config .gitleaks.toml .` → `no leaks found`, exit 0.

- **Dependency lock:** `requirements.lock` có 11 package, package nào cũng có `--hash=sha256:`; `pip install --require-hashes -r requirements.lock` thành công.

- **Before/after:**
  - `reports/attack-before.log` (299 byte): 1 dòng `POST /reconcile` chứa record synthetic `KH-000999`. Chạy lúc runner còn là stub, lệnh `python -m agent.loop --mock "Tổng hợp các ticket còn mở tuần này"`.
  - `reports/attack-after.log` (**0 byte**). Trình tự: reset sink → `pytest tests/ -q` → reset sink → `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` → copy `sink.log`.

- **Ledger verify:** `verify(Path('reports/ledger.jsonl'))` → `True`. Ledger có 46 dòng: 1–23 là run `--as dpo`, 24–46 là run `--as support_l1` chạy thêm sau khi đã copy `attack-after.log` (sink vẫn 0 byte). Mọi dòng có `reason`, `on_behalf_of`, `run_id`, `expires_at`. Dòng 2 và 25: `http_post` **deny**, reason `restricted + egress`. Dòng 26: `read_customer` deny cho `support_l1`. Đã thử sửa 1 ký tự ở dòng giữa một ledger tạm mà không tính lại hash → `verify()` trả `False`.

- **Các lỗi còn lại / lưu ý:**
  - README ghi Windows native chưa được pilot. Trên Windows, các script in tiếng Việt (ví dụ `python sink/sink.py --reset`) bị `UnicodeEncodeError` với code page cp1252 nếu không đặt `PYTHONIOENCODING=utf-8`. Tái hiện: chạy `python sink/sink.py --reset` trong PowerShell mặc định. Lệnh reset vẫn xoá log trước khi lỗi ở dòng `print`. Mọi lệnh trong bài đều chạy với `PYTHONIOENCODING=utf-8`.
  - `requirements.lock` sinh trên Windows nên có `colorama==0.4.6` (phụ thuộc của pytest chỉ trên Windows), không kèm platform marker. Trên Linux/macOS gói này vẫn được cài (vô hại); muốn lock đúng cho từng nền tảng thì phải sinh lại trên nền tảng đó.
  - Compliance mapping **chưa xác minh** số điều/khoản của Luật 91/2025, NĐ 356/2025, Luật 134/2025 với văn bản gốc.
  - Không làm bonus.

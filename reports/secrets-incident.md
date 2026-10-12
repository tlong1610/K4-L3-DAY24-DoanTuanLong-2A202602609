# Secret giả trong lịch sử Git — checkpoint 4

> Đây là **token giả, vô hiệu** do đề bài cài sẵn (định dạng `LAB24-DEMO`), không phải sự cố bảo mật thật. Note này viết như một incident thật để luyện quy trình.

- **Scanner và phiên bản:** Gitleaks **8.30.1** (`gitleaks version`), binary Windows x64 từ release chính thức, SHA256 `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e` khớp `gitleaks_8.30.1_checksums.txt`. Cấu hình `.gitleaks.toml` (`useDefault = true` + rule riêng `lab24-synthetic-token`).

- **Commit chứa token giả:** `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`, "chore: seed student lab with synthetic secret exercise"). File bị xoá ở commit kế tiếp `ece6ca4` nhưng blob vẫn còn trong lịch sử và trên remote.

- **File, rule và kết quả quét lịch sử:**
  ```
  gitleaks git --config .gitleaks.toml --redact --verbose .
  RuleID:      lab24-synthetic-token
  File:        lab-fake-secret.txt
  Line:        1
  Commit:      1bdd849922156c868a5ee9293d68f5b72e242d2c
  Fingerprint: 1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1
  INF 7 commits scanned.   WRN leaks found: 1   (exit code 1 — đúng dự kiến)
  ```
  Giá trị secret được `--redact` che trong output; note này không chép lại token.

- **Kết quả quét file hiện tại:** `gitleaks dir --config .gitleaks.toml .` → `no leaks found`, exit 0. HEAD sạch.

- **Phòng ngừa đã thêm:**
  - `.pre-commit-config.yaml`: hook `gitleaks-system` từ `https://github.com/gitleaks/gitleaks`, pin `rev: v8.30.1`, `pass_filenames: false`, `--config .gitleaks.toml`. `pre-commit run --all-files` → Passed. Thử stage một file chứa token giả cùng định dạng → hook **Failed** với `RuleID: lab24-synthetic-token`, `leaks found: 1`; file thử đã gỡ khỏi stage và xoá, không commit.
  - `requirements.lock`: sinh bằng `pip-compile --generate-hashes`, 11 package đều có `--hash=sha256:`; `pip install --require-hashes -r requirements.lock` chạy thành công. Lock sinh trên Windows nên có `colorama` (phụ thuộc của pytest chỉ trên Windows).

- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. **Thu hồi / rotate ngay** credential ở hệ thống phát hành (revoke token cũ, cấp token mới, cập nhật nơi dùng qua secret manager hoặc biến môi trường, không đưa lại vào repo). Coi như đã lộ từ thời điểm push `1bdd849`.
  2. Kiểm log truy cập của dịch vụ từ thời điểm đó để tìm việc dùng trái phép; mở incident theo quy trình, báo chủ sở hữu hệ thống.
  3. Sau khi đã rotate, mới cân nhắc viết lại lịch sử (`git filter-repo`), force-push và yêu cầu mọi người clone lại; báo nền tảng (GitHub) xoá cache, PR, fork nếu cần. Bước này chỉ giảm phơi nhiễm, không thay cho rotate.
  4. Bài lab **không** viết lại lịch sử: commit token giả phải còn để chấm checkpoint 4.

- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:**
  - Xoá file ở `ece6ca4` chỉ làm HEAD sạch; blob vẫn nằm trong `1bdd849`, trong mọi clone, fork, cache CI và bất kỳ ai đã fetch. Ai có lịch sử là có secret, nên credential vẫn dùng được cho tới khi bị **thu hồi**.
  - Hook pre-commit chỉ chặn commit **tương lai** trên máy đã cài hook (và có thể bị bỏ qua bằng `--no-verify`); nó không quét lại hay sửa được lịch sử đã push. Nên chạy thêm gitleaks trong CI.
  - Pin version và hash lock bảo vệ **chuỗi cung ứng dependency** (chống package bị thay, nâng version ngoài ý muốn); nó không liên quan tới việc secret của mình đã lộ. Credential đã lộ chỉ hết nguy hiểm khi bị rotate hoặc thu hồi.

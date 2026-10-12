"""Bonus — delete cascade giữ ledger verify (agent/erasure.py).

    python -m pytest tests/test_bonus_erasure.py -v -s

Chạy trên BẢN SAO tạm của customers.json và corpus/, không đụng dữ liệu repo.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agent import tools
from agent.erasure import ERASED_MARKER, erase_customer
from agent.ledger import verify
from agent.loop import run_once

ROOT = Path(__file__).resolve().parent.parent
VICTIM = "KH-000999"
QUERY = "Tổng hợp các ticket còn mở tuần này"


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus"
    shutil.copytree(ROOT / "corpus", corpus)
    customers = tmp_path / "customers.json"
    shutil.copy(ROOT / "data" / "customers.json", customers)
    monkeypatch.setattr(tools, "CORPUS_DIR", corpus)
    monkeypatch.setattr(tools, "CUSTOMERS_FILE", customers)
    victim = next(c for c in json.loads(customers.read_text(encoding="utf-8")) if c["customer_id"] == VICTIM)
    return {"corpus": corpus, "customers": customers, "ledger": tmp_path / "ledger.jsonl",
            "log_dir": tmp_path, "victim": victim}


def _reads_during_run(monkeypatch, log_dir: Path) -> list[str]:
    seen = []
    real = tools.read_customer
    monkeypatch.setattr(tools, "read_customer", lambda cid, *a, **k: (seen.append(cid), real(cid, *a, **k))[1])
    run_once(QUERY, mock=True, log_dir=log_dir, principal_id="dpo")
    monkeypatch.setattr(tools, "read_customer", real)
    return seen


def test_support_l1_cannot_erase(sandbox):
    result = erase_customer(VICTIM, "support_l1", ledger_path=sandbox["ledger"])
    assert result["erased"] is False
    assert tools.read_customer(VICTIM)["customer_id"] == VICTIM
    entry = json.loads(sandbox["ledger"].read_text(encoding="utf-8").splitlines()[-1])
    assert entry["tool"] == "erase_customer" and entry["decision"] == "deny" and entry["reason"]


def test_erasure_cascades_and_ledger_still_verifies(sandbox, clean_sink, monkeypatch):
    # 1. Có lịch sử xử lý thật trước khi xoá: dpo đã đọc hồ sơ nạn nhân.
    assert VICTIM in _reads_during_run(monkeypatch, sandbox["log_dir"])
    lines_before = sandbox["ledger"].read_text(encoding="utf-8").splitlines()
    assert verify(sandbox["ledger"])

    # 2. Xoá theo yêu cầu.
    result = erase_customer(VICTIM, "dpo", ledger_path=sandbox["ledger"])
    print(f"\n[erasure] {result}")
    assert result["erased"] and result["ledger_verified_before"] and result["ledger_verified_after"]
    assert sorted(result["tickets_scrubbed"]) == ["ticket-901.md", "ticket-902.md", "ticket-903.md", "ticket-904.md"]

    # 3. Cascade: không còn ở kho khách, không còn trong ticket.
    with pytest.raises(tools.ToolError):
        tools.read_customer(VICTIM)
    for path in sandbox["corpus"].glob("*.md"):
        assert VICTIM not in path.read_text(encoding="utf-8"), path.name
    assert ERASED_MARKER in (sandbox["corpus"] / "ticket-901.md").read_text(encoding="utf-8")

    # 4. Ledger: các dòng cũ giữ nguyên từng byte, chain vẫn verify, không có PII thô.
    lines_after = sandbox["ledger"].read_text(encoding="utf-8").splitlines()
    assert lines_after[: len(lines_before)] == lines_before
    assert verify(sandbox["ledger"])
    ledger_text = sandbox["ledger"].read_text(encoding="utf-8")
    for field in ("cccd", "phone", "bank_account", "email", "name", "customer_id"):
        assert sandbox["victim"][field] not in ledger_text, f"ledger chứa {field} thô"

    # 5. Agent vẫn chạy được sau khi xoá, nhưng không còn đọc tới nạn nhân.
    reads_after = _reads_during_run(monkeypatch, sandbox["log_dir"])
    assert reads_after and VICTIM not in reads_after
    assert verify(sandbox["ledger"])
    print(f"[erasure] ledger {len(lines_before)} dòng trước xoá -> "
          f"{len(sandbox['ledger'].read_text(encoding='utf-8').splitlines())} dòng sau, verify=True; "
          f"run lại đọc {len(reads_after)} khách, không có {VICTIM}")


def _victim_args_hash() -> str:
    import hashlib
    return hashlib.sha256(json.dumps({"customer_id": VICTIM}, sort_keys=True).encode("utf-8")).hexdigest()


def test_deleting_ledger_lines_instead_would_break_the_chain(sandbox, clean_sink, monkeypatch):
    """Phản chứng: 'quên' khách bằng cách xoá dòng ledger của họ làm verify() thất bại."""
    _reads_during_run(monkeypatch, sandbox["log_dir"])
    _reads_during_run(monkeypatch, sandbox["log_dir"])  # 2 phiên: dòng của nạn nhân nằm giữa file
    lines = sandbox["ledger"].read_text(encoding="utf-8").splitlines()
    victim_lines = [i for i, line in enumerate(lines) if json.loads(line)["args_hash"] == _victim_args_hash()]
    assert len(victim_lines) == 2 and victim_lines[0] < len(lines) - 1

    kept = [line for i, line in enumerate(lines) if i not in victim_lines]
    sandbox["ledger"].write_text("\n".join(kept) + "\n", encoding="utf-8")
    assert verify(sandbox["ledger"]) is False


def test_known_limit_tail_truncation_is_not_detected(sandbox, clean_sink, monkeypatch):
    """Giới hạn đã nêu trong README: cắt dòng cuối không bị hash chain phát hiện."""
    _reads_during_run(monkeypatch, sandbox["log_dir"])
    lines = sandbox["ledger"].read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[-1])["args_hash"] == _victim_args_hash()  # KH-000999 được đọc cuối cùng
    sandbox["ledger"].write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    assert verify(sandbox["ledger"]) is True  # cần mốc tin cậy bên ngoài (hash/số dòng cuối) mới bắt được


def test_repo_data_is_untouched():
    customers = json.loads((ROOT / "data" / "customers.json").read_text(encoding="utf-8"))
    assert any(c["customer_id"] == VICTIM for c in customers)
    assert VICTIM in (ROOT / "corpus" / "ticket-901.md").read_text(encoding="utf-8")

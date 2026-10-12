"""Bonus — xoá dữ liệu một khách theo yêu cầu (delete cascade), ledger vẫn verify.

    erase_customer("KH-000999", principal_id="dpo")

Cascade:
  1. PEP: tool `erase_customer`, purpose `erasure-request`, classification
     restricted, không egress. Deny thì ghi ledger và dừng.
  2. Xoá record khỏi customers.json (ghi file tạm rồi thay thế).
  3. Với mỗi ticket trong `related_tickets` của khách: thay mã khách bằng
     `[ERASED_CUSTOMER]` và redact PII còn sót trong nội dung ticket.
  4. Ledger KHÔNG bị sửa hay xoá dòng nào — vốn chỉ chứa `args_hash`, không
     có PII thô — nên hash chain vẫn verify; chỉ append thêm một dòng ghi nhận.

Xoá dòng ledger để "quên" khách sẽ làm đứt hash chain: đó là lý do ledger
phải được thiết kế không chứa PII ngay từ đầu.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

ERASED_MARKER = "[ERASED_CUSTOMER]"
DEFAULT_LEDGER_PATH = Path(__file__).resolve().parent.parent / "reports" / "ledger.jsonl"


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def erase_customer(customer_id: str, principal_id: str, *, customers_file: Path | None = None,
                   corpus_dir: Path | None = None, ledger_path: Path | None = None) -> dict:
    customers_file = customers_file or tools.CUSTOMERS_FILE
    corpus_dir = corpus_dir or tools.CORPUS_DIR
    ledger_path = ledger_path or DEFAULT_LEDGER_PATH
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    args_hash = hashlib.sha256(json.dumps({"customer_id": customer_id}).encode("utf-8")).hexdigest()

    def log(decision: str, reason: str) -> None:
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-agent/erasure",
            "run_id": f"{uuid.uuid4().hex[:12]}-erasure",
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": "erase_customer",
            "args_hash": args_hash,
            "classification": "restricted",
            "purpose": "erasure-request",
            "delegation_depth": 0,
            "decision": decision,
            "reason": reason,
        }, ledger_path)

    allow, reason = check(PolicyContext(
        data_classification="restricted", request_purpose="erasure-request",
        agent_owner="lab24-agent/erasure", delegation_depth=0, egress_enabled=False,
        principal_id=principal_id, requested_tool="erase_customer",
        agent_scopes=("erase_customer",), expires_at=expires_at,
    ))
    if not allow:
        log("deny", reason)
        return {"erased": False, "reason": reason}

    customers = json.loads(customers_file.read_text(encoding="utf-8"))
    target = next((c for c in customers if c["customer_id"] == customer_id), None)
    if target is None:
        log("allow", f"{reason}; không tìm thấy record, không có gì để xoá")
        return {"erased": False, "reason": "không tìm thấy record"}

    ledger_ok_before = verify_or_empty(ledger_path)
    remaining = [c for c in customers if c["customer_id"] != customer_id]
    _atomic_write(customers_file, json.dumps(remaining, ensure_ascii=False, indent=2) + "\n")

    scrubbed = []
    for ticket_id in target.get("related_tickets", []):
        path = corpus_dir / f"ticket-{ticket_id:03d}.md"
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        cleaned = pii.redact(text.replace(customer_id, ERASED_MARKER))
        if cleaned != text:
            _atomic_write(path, cleaned)
            scrubbed.append(path.name)

    log("allow", f"{reason}; đã xoá record khỏi {customers_file.name}, scrub {len(scrubbed)} ticket, "
                 f"ledger giữ nguyên (chỉ có args_hash)")
    return {
        "erased": True,
        "tickets_scrubbed": scrubbed,
        "ledger_verified_before": ledger_ok_before,
        "ledger_verified_after": ledger.verify(ledger_path),
    }


def verify_or_empty(path: Path) -> bool:
    return ledger.verify(path) if Path(path).exists() else True

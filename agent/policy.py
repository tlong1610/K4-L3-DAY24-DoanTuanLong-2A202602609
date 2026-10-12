"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
CLASSIFICATIONS = ("public", "internal", "restricted")


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def load_principals(path: Path | None = None) -> dict:
    return json.loads((path or PRINCIPALS_FILE).read_text(encoding="utf-8"))


def _parse_expiry(value: str) -> datetime | None:
    try:
        expires = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    # Không có timezone thì không so được với UTC một cách chắc chắn -> coi như hỏng.
    return expires if expires.tzinfo is not None else None


def check(context: PolicyContext) -> tuple[bool, str]:
    """Fail closed: mọi nhánh không chứng minh được quyền đều deny."""
    c = context
    tool = c.requested_tool or "<không rõ tool>"

    # Rule tối thiểu đứng đầu: không quyền nào gỡ được nó.
    if c.data_classification == "restricted" and c.egress_enabled:
        return False, (f"deny {tool}: dữ liệu restricted không được đi kèm egress "
                       f"(rule tối thiểu restricted + egress)")
    if c.data_classification not in CLASSIFICATIONS:
        return False, f"deny {tool}: classification không hợp lệ {c.data_classification!r}"

    expires = _parse_expiry(c.expires_at)
    if expires is None:
        return False, f"deny {tool}: thiếu hoặc sai expires_at {c.expires_at!r} (cần ISO-8601 có timezone)"
    if expires <= datetime.now(timezone.utc):
        return False, f"deny {tool}: run đã hết hạn lúc {c.expires_at}"

    principal = load_principals().get(c.principal_id)
    if principal is None:
        return False, f"deny {tool}: principal không có trong data/principals.json ({c.principal_id!r})"
    if c.request_purpose not in principal.get("purposes", []):
        return False, (f"deny {tool}: purpose {c.request_purpose!r} không được phép cho "
                       f"principal {c.principal_id}")

    if not c.requested_tool:
        return False, "deny: thiếu requested_tool"
    if c.delegation_depth < 0:
        return False, f"deny {tool}: delegation_depth âm ({c.delegation_depth})"

    # Quyền hiệu lực = giao của mọi tầng; thiếu ở bất kỳ tầng nào là deny.
    layers = [("principal.allowed_tools", tuple(principal.get("allowed_tools", []))),
              ("agent_scopes", c.agent_scopes)]
    if c.delegation_depth > 0:
        layers.append(("parent_scopes", c.parent_scopes))
    for name, scopes in layers:
        if tool not in scopes:
            return False, (f"deny {tool}: không nằm trong {name} của {c.principal_id} "
                           f"(depth={c.delegation_depth})")

    return True, (f"allow {tool}: {c.principal_id} có quyền cho purpose {c.request_purpose!r}, "
                  f"classification={c.data_classification}, egress={c.egress_enabled}, "
                  f"depth={c.delegation_depth}")

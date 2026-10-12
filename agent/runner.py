"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_TTL = timedelta(minutes=5)
# Scope tối đa của từng run. Không run nào cầm đủ 3 chân trifecta, và không
# run nào có http_post: egress chỉ tồn tại dưới dạng yêu cầu bị PEP xét.
ORCHESTRATOR_SCOPES = ("search_docs", "read_customer")
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("read_customer",)
_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


@dataclass(frozen=True)
class _Session:
    principal_id: str
    session_id: str
    expires_at: str
    ledger_path: Path


def _args_hash(args: dict) -> str:
    # Ledger chỉ giữ hash của tham số, không giữ PII/ID thô.
    return hashlib.sha256(json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _guarded_call(session: _Session, *, run: str, tool: str, args: dict, classification: str,
                  purpose: str, depth: int, egress: bool, agent_scopes: tuple[str, ...],
                  parent_scopes: tuple[str, ...] = (), call=None):
    """PEP: policy.check() -> ledger.append() (cả allow lẫn deny) -> mới chạy tool."""
    agent_id = f"{AGENT_ID}/run-{run}"
    context = PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=agent_id,
        delegation_depth=depth,
        egress_enabled=egress,
        principal_id=session.principal_id,
        requested_tool=tool,
        agent_scopes=agent_scopes,
        parent_scopes=parent_scopes,
        expires_at=session.expires_at,
    )
    allow, reason = _policy_check(context)
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "run_id": f"{session.session_id}-{run}",
        "on_behalf_of": session.principal_id,
        "expires_at": session.expires_at,
        "tool": tool,
        "args_hash": _args_hash(args),
        "classification": classification,
        "purpose": purpose,
        "delegation_depth": depth,
        "decision": "allow" if allow else "deny",
        "reason": reason,
    }, session.ledger_path)
    if not allow or call is None:
        return allow, None
    return True, call()


def _ticket_ids(docs: list[dict]) -> list[int]:
    """Chỉ lấy số từ TÊN FILE; nội dung document không bao giờ được đọc ở đây."""
    ids = set()
    for doc in docs:
        match = _TICKET_FILE_RE.match(doc["id"])
        if match:
            ids.add(int(match.group(1)))
    return sorted(ids)


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Nguồn tin cậy ticket_id -> customer_id: related_tickets trong customers.json."""
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    wanted = set(ticket_ids)
    return sorted(c["customer_id"] for c in customers if wanted & set(c.get("related_tickets", [])))


def _run_a(session: _Session, message: str, llm) -> tuple[list[dict], list[int]]:
    """Untrusted content: chỉ search_docs. Trả docs đã redact + list[int] ticket id."""
    allowed, docs = _guarded_call(
        session, run="a", tool="search_docs", args={"query": message},
        classification="internal", purpose="summarize-tickets", depth=0, egress=False,
        agent_scopes=RUN_A_SCOPES, call=lambda: tools.search_docs(message),
    )
    if not allowed:
        return [], []

    # PII gate trước khi bất kỳ text nào đi tiếp vào context.
    redacted = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]

    injected = llm.find_injection("\n\n".join(d["text"] for d in redacted))
    if injected is not None:
        # Model "muốn" làm theo chỉ thị trong tài liệu. Yêu cầu đó vẫn phải qua
        # PEP: payload là hồ sơ khách (restricted) + egress -> bị deny, tool
        # không chạy. customer_ids từ free text không được dùng ở bất kỳ đâu.
        _guarded_call(
            session, run="a", tool="http_post",
            args={"url": injected.target_url, "customer_ids": injected.customer_ids},
            classification="restricted", purpose="summarize-tickets", depth=0, egress=True,
            agent_scopes=RUN_A_SCOPES,
        )
    return redacted, _ticket_ids(docs)


def _run_b(session: _Session, ticket_ids: list[int]) -> list[dict]:
    """Private data: chỉ read_customer, input duy nhất là list[int] đã typed."""
    if not all(isinstance(t, int) for t in ticket_ids):
        raise TypeError("Run B chỉ nhận list[int] ticket id")
    records = []
    for customer_id in _customers_for_tickets(ticket_ids):
        allowed, record = _guarded_call(
            session, run="b", tool="read_customer", args={"customer_id": customer_id},
            classification="restricted", purpose="support-reply", depth=1, egress=False,
            agent_scopes=RUN_B_SCOPES, parent_scopes=ORCHESTRATOR_SCOPES,
            call=lambda cid=customer_id: tools.read_customer(cid),
        )
        if allowed:
            records.append(record)
    return records


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    session = _Session(
        principal_id=principal_id,
        session_id=uuid.uuid4().hex[:12],
        expires_at=(datetime.now(timezone.utc) + RUN_TTL).isoformat(),
        ledger_path=(Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH,
    )
    docs, ticket_ids = _run_a(session, message, llm)
    if not docs:
        return llm.summarize([])
    # Run B chỉ phục vụ việc hợp lệ trong phiên; hồ sơ không đi ra ngoài.
    _run_b(session, ticket_ids)
    return llm.summarize(docs)


def _policy_check(context: PolicyContext) -> tuple[bool, str]:
    """PDP mặc định là agent/policy.py; LAB24_POLICY_ENGINE=opa dùng bản Rego (bonus)."""
    import os

    if os.environ.get("LAB24_POLICY_ENGINE", "python").lower() == "opa":
        from agent import policy_opa

        allow, reason = policy_opa.check(context)
        return allow, f"[opa] {reason}"
    return check(context)

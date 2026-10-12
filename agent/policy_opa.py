"""Bonus — PEP gọi OPA thay cho agent/policy.py.

Cùng interface `check(PolicyContext) -> (allow, reason)`. Runner dùng engine
này khi đặt LAB24_POLICY_ENGINE=opa. Lỗi gọi OPA (thiếu binary, lỗi Rego,
output lạ) đều trả deny kèm reason — không bao giờ fail open.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict
from pathlib import Path

from agent.policy import PolicyContext, load_principals

POLICY_FILE = Path(__file__).resolve().parent.parent / "policy" / "lab24.rego"
QUERY = "data.lab24.policy.decisions"


def _case(context: PolicyContext) -> dict:
    case = asdict(context)
    case["agent_scopes"] = list(context.agent_scopes)
    case["parent_scopes"] = list(context.parent_scopes)
    return case


def check_many(contexts: list[PolicyContext]) -> list[tuple[bool, str]]:
    """Đánh giá nhiều context trong một lần gọi `opa eval`."""
    opa = shutil.which("opa")
    if opa is None:
        return [(False, "deny: không tìm thấy binary opa trong PATH (fail closed)")] * len(contexts)
    payload = {"principals": load_principals(), "cases": [_case(c) for c in contexts]}
    try:
        proc = subprocess.run(
            [opa, "eval", "--format", "json", "--stdin-input", "-d", str(POLICY_FILE), QUERY],
            input=json.dumps(payload, ensure_ascii=False), capture_output=True,
            text=True, encoding="utf-8", timeout=30, check=False,
        )
        decisions = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError) as exc:
        return [(False, f"deny: lỗi khi gọi OPA ({type(exc).__name__}) (fail closed)")] * len(contexts)
    if len(decisions) != len(contexts):
        return [(False, "deny: OPA trả số decision không khớp (fail closed)")] * len(contexts)
    return [(d.get("allow") is True, d.get("reason") or "deny: OPA không trả reason")
            for d in decisions]


def check(context: PolicyContext) -> tuple[bool, str]:
    return check_many([context])[0]

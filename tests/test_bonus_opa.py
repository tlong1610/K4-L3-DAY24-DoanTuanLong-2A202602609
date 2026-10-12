"""Bonus — policy port sang OPA/Rego (policy/lab24.rego).

    python -m pytest tests/test_bonus_opa.py -v

Skip nếu máy không có binary `opa` trong PATH (không ảnh hưởng phần bắt buộc).
"""
from __future__ import annotations

import itertools
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agent import policy, policy_opa
from agent.loop import run_once
from agent.policy import PolicyContext

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="cần binary opa trong PATH")

FUTURE = "2099-01-01T00:00:00+00:00"


def _grid() -> list[PolicyContext]:
    contexts = []
    for (classification, egress, principal, tool, purpose, (depth, parent), expires) in itertools.product(
        ("public", "internal", "restricted", "secret"),
        (False, True),
        ("support_l1", "billing", "dpo", "nobody"),
        ("search_docs", "read_customer", "http_post", ""),
        ("summarize-tickets", "support-reply", "billing-reconciliation"),
        ((0, ()), (1, ("search_docs",)), (1, ("search_docs", "read_customer")), (-1, ())),
        (FUTURE, "2000-01-01T00:00:00+00:00", "", "not-a-date", "2099-01-01T00:00:00Z"),
    ):
        contexts.append(PolicyContext(
            data_classification=classification, request_purpose=purpose,
            agent_owner="lab24-agent/test", delegation_depth=depth, egress_enabled=egress,
            principal_id=principal, requested_tool=tool,
            agent_scopes=("search_docs", "read_customer"), parent_scopes=parent,
            expires_at=expires,
        ))
    return contexts


def test_rego_unit_tests_pass():
    proc = subprocess.run(["opa", "test", str(ROOT / "policy"), "-v"],
                          capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_opa_matches_python_on_every_context():
    contexts = _grid()
    opa_results = policy_opa.check_many(contexts)
    mismatches = []
    for ctx, (opa_allow, opa_reason) in zip(contexts, opa_results):
        py_allow, py_reason = policy.check(ctx)
        assert opa_reason, f"OPA trả reason rỗng cho {ctx}"
        if opa_allow != py_allow:
            mismatches.append((ctx, py_reason, opa_reason))
    print(f"\n[opa] {len(contexts)} context, {len(mismatches)} lệch so với agent/policy.py, "
          f"{sum(a for a, _ in opa_results)} allow")
    assert not mismatches, mismatches[:3]


def test_opa_fails_closed_without_binary(monkeypatch):
    monkeypatch.setattr(policy_opa.shutil, "which", lambda name: None)
    allow, reason = policy_opa.check(_grid()[0])
    assert allow is False and "fail closed" in reason


@pytest.mark.parametrize("principal", ["support_l1", "dpo"])
def test_agent_runs_end_to_end_on_opa(principal, clean_sink, tmp_path, monkeypatch):
    from agent import tools

    reads = []
    real_read = tools.read_customer
    monkeypatch.setattr(tools, "read_customer", lambda cid, *a, **k: (reads.append(cid), real_read(cid, *a, **k))[1])
    monkeypatch.setenv("LAB24_POLICY_ENGINE", "opa")

    run_once("Tổng hợp các ticket còn mở tuần này", mock=True, log_dir=tmp_path, principal_id=principal)

    entries = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]
    assert entries and all(e["reason"].startswith("[opa] ") for e in entries)
    posts = [e for e in entries if e["tool"] == "http_post"]
    assert posts and all(e["decision"] == "deny" for e in posts)
    if principal == "support_l1":
        assert not reads
    else:
        assert "KH-000999" in reads

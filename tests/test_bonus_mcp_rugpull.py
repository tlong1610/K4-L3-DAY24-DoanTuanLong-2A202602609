"""Bonus — MCP rug pull local (bonus/mcp_rugpull_server.py + agent/mcp_guard.py).

    python -m pytest tests/test_bonus_mcp_rugpull.py -v -s

1. Agent ngây thơ: tin mô tả tool mới -> làm theo -> PII synthetic ra sink.
2. Agent có PinnedToolGuard: phát hiện định nghĩa tool đổi -> deny, sink rỗng.
"""
from __future__ import annotations

import json

from agent import tools
from agent.ledger import verify
from agent.llm import find_injection
from agent.mcp_guard import PinnedToolGuard, StdioMCPClient, rugpull_server_command, tool_fingerprint
from sink.sink import LOG_PATH as SINK_LOG_PATH

VICTIM = "KH-000999"


def _victim_values() -> list[str]:
    record = tools.read_customer(VICTIM)
    return [record["cccd"], record["bank_account"], record["phone"]]


def test_server_rug_pulls_after_first_call():
    with StdioMCPClient(rugpull_server_command()) as client:
        before = client.list_tools()[0]
        result = client.call_tool("ticket_lookup", {"ticket_id": 1})
        after = client.list_tools()[0]
    assert "Ticket" in result["content"][0]["text"]
    assert before["name"] == after["name"] == "ticket_lookup"
    assert tool_fingerprint(before) != tool_fingerprint(after)
    assert find_injection(before["description"]) is None
    injected = find_injection(after["description"])
    assert injected is not None and injected.customer_ids == [VICTIM]
    print(f"\n[rugpull] mô tả sau lần gọi đầu: {after['description']!r}")


def test_naive_agent_follows_rug_pulled_description(clean_sink):
    """Trước khi có guard: agent đọc lại tools/list và làm theo mô tả mới."""
    with StdioMCPClient(rugpull_server_command()) as client:
        client.list_tools()
        client.call_tool("ticket_lookup", {"ticket_id": 1})
        description = client.list_tools()[0]["description"]
        injected = find_injection(description)
        assert injected is not None
        records = [tools.read_customer(cid) for cid in injected.customer_ids]
        tools.http_post(injected.target_url, {"records": records})

    sink = SINK_LOG_PATH.read_text(encoding="utf-8")
    assert "/mcp-exfil" in sink
    assert all(value in sink for value in _victim_values()), "rug pull phải rò được record synthetic"
    print(f"\n[rugpull] naive agent -> sink nhận {len(sink.encode('utf-8'))} byte tại /mcp-exfil")


def test_pinned_guard_blocks_rug_pull(clean_sink, tmp_path, monkeypatch):
    posts = []
    monkeypatch.setattr(tools, "http_post", lambda *a, **k: posts.append(a))
    ledger_path = tmp_path / "ledger.jsonl"

    with StdioMCPClient(rugpull_server_command()) as client:
        guard = PinnedToolGuard(client, ledger_path, principal_id="dpo")
        pins = guard.approve()
        first = guard.call("ticket_lookup", {"ticket_id": 1})
        second = guard.call("ticket_lookup", {"ticket_id": 2})
        unknown = guard.call("delete_everything", {})

    assert "ticket_lookup" in pins
    assert first is not None and "Ticket" in first["content"][0]["text"], "tool hợp lệ vẫn phải dùng được"
    assert second is None, "guard phải chặn lần gọi sau khi định nghĩa tool đổi"
    assert unknown is None
    assert not posts
    assert SINK_LOG_PATH.read_text(encoding="utf-8") == ""

    entries = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    assert verify(ledger_path)
    assert [e["decision"] for e in entries] == ["allow", "allow", "deny", "deny"]
    assert "rug pull" in entries[2]["reason"]
    assert all(e["on_behalf_of"] == "dpo" and e["reason"] for e in entries)
    for e in entries:
        print(f"[rugpull] ledger {e['tool']:22s} {e['decision']:5s} | {e['reason']}")

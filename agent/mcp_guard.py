"""Bonus — chống MCP rug pull bằng cách pin định nghĩa tool lúc duyệt.

Lúc người dùng duyệt MCP server, ta ghi fingerprint SHA-256 của từng tool
(name + description + inputSchema). Trước MỖI lần gọi, liệt kê lại tool và so
fingerprint: đổi bất kỳ chữ nào -> deny, ghi ledger, không gọi tool, và mô tả
mới không được đưa vào context của model. Muốn dùng tiếp phải duyệt lại.

Mô tả tool là dữ liệu do server bên thứ ba kiểm soát, giống nội dung ticket ở
checkpoint 2: không phải kênh điều khiển đáng tin.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger

ROOT = Path(__file__).resolve().parent.parent
RUGPULL_SERVER = ROOT / "bonus" / "mcp_rugpull_server.py"
PROTOCOL_VERSION = "2025-06-18"


def tool_fingerprint(tool: dict) -> str:
    pinned = {k: tool.get(k) for k in ("name", "description", "inputSchema")}
    return hashlib.sha256(json.dumps(pinned, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


class StdioMCPClient:
    """Client MCP tối giản qua stdio (JSON-RPC 2.0, mỗi message một dòng)."""

    def __init__(self, command: list[str]):
        self._proc = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, encoding="utf-8", bufsize=1,
        )
        self._next_id = 0
        self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "lab24-agent", "version": "0.1.0"},
        })
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, msg: dict) -> None:
        self._proc.stdin.write(json.dumps(msg, ensure_ascii=False) + "\n")
        self._proc.stdin.flush()

    def _request(self, method: str, params: dict) -> dict:
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params})
        reply = json.loads(self._proc.stdout.readline())
        if "error" in reply:
            raise RuntimeError(reply["error"])
        return reply["result"]

    def list_tools(self) -> list[dict]:
        return self._request("tools/list", {})["tools"]

    def call_tool(self, name: str, arguments: dict) -> dict:
        return self._request("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        self._proc.stdin.close()
        self._proc.wait(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class PinnedToolGuard:
    """PEP cho MCP tool call: chỉ cho gọi tool có định nghĩa khớp bản đã duyệt."""

    def __init__(self, client: StdioMCPClient, ledger_path: Path, principal_id: str):
        self.client = client
        self.ledger_path = ledger_path
        self.principal_id = principal_id
        self.run_id = f"{uuid.uuid4().hex[:12]}-mcp"
        self.expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        self.pins: dict[str, str] = {}

    def _log(self, tool: str, args: dict, decision: str, reason: str) -> None:
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-agent/mcp",
            "run_id": self.run_id,
            "on_behalf_of": self.principal_id,
            "expires_at": self.expires_at,
            "tool": f"mcp:{tool}",
            "args_hash": hashlib.sha256(json.dumps(args, sort_keys=True).encode("utf-8")).hexdigest(),
            "classification": "internal",
            "decision": decision,
            "reason": reason,
        }, self.ledger_path)

    def approve(self) -> dict[str, str]:
        """Mô phỏng bước người dùng duyệt server: pin fingerprint hiện tại."""
        for tool in self.client.list_tools():
            self.pins[tool["name"]] = tool_fingerprint(tool)
            self._log(tool["name"], {}, "allow",
                      f"approve mcp:{tool['name']}: pin sha256={self.pins[tool['name']][:16]}…")
        return dict(self.pins)

    def call(self, name: str, arguments: dict) -> dict | None:
        current = {t["name"]: t for t in self.client.list_tools()}
        if name not in self.pins:
            self._log(name, arguments, "deny", f"deny mcp:{name}: tool chưa được duyệt")
            return None
        if name not in current:
            self._log(name, arguments, "deny", f"deny mcp:{name}: server không còn tool này")
            return None
        now = tool_fingerprint(current[name])
        if now != self.pins[name]:
            self._log(name, arguments, "deny",
                      f"deny mcp:{name}: rug pull — định nghĩa tool đổi sau khi duyệt "
                      f"(pinned {self.pins[name][:16]}…, hiện {now[:16]}…); cần duyệt lại")
            return None
        self._log(name, arguments, "allow", f"allow mcp:{name}: fingerprint khớp bản đã duyệt")
        return self.client.call_tool(name, arguments)


def rugpull_server_command() -> list[str]:
    return [sys.executable, str(RUGPULL_SERVER)]

#!/usr/bin/env python3
"""A small MCP stdio client for checking the meguvizdexdash server.

It speaks JSON-RPC 2.0 one message per line, keeps no state beyond the pipe, and
reports protocol errors as `McpError` instead of hiding them in a tool result.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BINARY = ROOT / "target" / "debug" / ("meguvizdexdash.exe" if os.name == "nt" else "meguvizdexdash")


class McpError(RuntimeError):
    def __init__(self, error: dict):
        super().__init__(json.dumps(error))
        self.error = error
        self.code = error.get("code")


class McpClient:
    def __init__(self, binary: Path | None = None, args: list[str] | None = None):
        self.process = subprocess.Popen([str(binary or DEFAULT_BINARY), "mcp", *(args or [])],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.next_id = 0

    def send_raw(self, line: bytes) -> None:
        self.process.stdin.write(line + b"\n")
        self.process.stdin.flush()

    def read_message(self) -> dict:
        raw = self.process.stdout.readline()
        if not raw:
            raise RuntimeError("the server closed stdout: " + self.process.stderr.read().decode("utf-8", "replace"))
        return json.loads(raw)

    def request(self, method: str, params: dict | None = None) -> dict:
        """The full JSON-RPC response object, error or not."""
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            message["params"] = params
        self.send_raw(json.dumps(message).encode("utf-8"))
        response = self.read_message()
        if response.get("id") != self.next_id:
            raise RuntimeError(f"answered another request: {response}")
        return response

    def notify(self, method: str, params: dict | None = None) -> None:
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.send_raw(json.dumps(message).encode("utf-8"))

    def initialize(self, version: str = "2025-06-18") -> dict:
        response = self.request("initialize", {"protocolVersion": version, "capabilities": {},
                                               "clientInfo": {"name": "mdd-check", "version": "1"}})
        self.notify("notifications/initialized")
        return response["result"]

    def tools(self) -> list[dict]:
        return self.request("tools/list")["result"]["tools"]

    def call(self, name: str, **arguments) -> dict:
        """The tool's structured content, with `_is_error`. A JSON-RPC error raises McpError."""
        response = self.request("tools/call", {"name": name, "arguments": arguments})
        if "error" in response:
            raise McpError(response["error"])
        result = response["result"]
        structured = dict(result["structuredContent"])
        text = json.loads(result["content"][0]["text"])
        if text != result["structuredContent"]:
            raise RuntimeError("the text content and the structured content differ")
        structured["_is_error"] = result["isError"]
        return structured

    def close(self) -> int:
        try:
            self.process.stdin.close()
        except OSError:
            pass
        code = self.process.wait(timeout=30)
        for stream in (self.process.stdout, self.process.stderr):
            stream.close()
        return code

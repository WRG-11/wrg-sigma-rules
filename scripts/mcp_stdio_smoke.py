"""Smoke-test an MCP stdio server by actually speaking the protocol to it.

Takes the server command as arguments, so the same check covers both
surfaces this repo ships:

    python scripts/mcp_stdio_smoke.py python server.py
    python scripts/mcp_stdio_smoke.py docker run -i --rm wrg-sigma-rules-mcp

It performs a real JSON-RPC handshake over stdin/stdout -- initialize,
initialized, tools/list, resources/list -- and asserts the server announces
the tools and resources this plugin is supposed to expose. That is a
stronger claim than "the image builds" or "the module imports": a server
that starts and then announces nothing would pass both of those and fail
this.

Exits 0 on success, 1 with a diagnostic on failure.
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

# Tool and resource names the plugin promises. Kept here rather than derived
# from the source so the check is an independent statement of the contract:
# deleting a registration in server.py should fail this, not silently
# redefine what "expected" means.
_EXPECTED_TOOLS = {"draft_rule", "validate_rule", "convert_rule"}
_EXPECTED_RESOURCES = {
    "wrg-sigma://patterns/canonical-5",
    "wrg-sigma://coverage/mitre-attack-matrix",
}

_PROTOCOL_VERSION = "2024-11-05"
_TIMEOUT_SECONDS = 60


def _request(request_id: int, method: str, params: dict[str, Any] | None = None) -> str:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        payload["params"] = params
    return json.dumps(payload)


def _notification(method: str, params: dict[str, Any] | None = None) -> str:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        payload["params"] = params
    return json.dumps(payload)


def _fail(message: str, stdout: str = "", stderr: str = "") -> int:
    print(f"FAIL: {message}", file=sys.stderr)
    if stdout:
        print("--- server stdout ---", file=sys.stderr)
        print(stdout[:4000], file=sys.stderr)
    if stderr:
        print("--- server stderr ---", file=sys.stderr)
        print(stderr[:4000], file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return _fail("no server command given")

    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        return _fail(f"server command not found: {argv[0]}")

    responses: dict[int, dict[str, Any]] = {}

    def send(line: str) -> None:
        assert proc.stdin is not None
        proc.stdin.write(line + "\n")
        proc.stdin.flush()

    def read_response(request_id: int) -> dict[str, Any] | None:
        """Read stdout until the reply to ``request_id`` arrives.

        The exchange is driven one request at a time rather than piping the
        whole conversation in at once: closing stdin immediately after the
        last request races the server, which can process it and exit before
        the reply is flushed. That race dropped the final response entirely
        when this script wrote everything up front.
        """
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(message, dict):
                continue
            if isinstance(message.get("id"), int):
                responses[message["id"]] = message
                if message["id"] == request_id:
                    return message
        return None

    try:
        send(
            _request(
                1,
                "initialize",
                {
                    "protocolVersion": _PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "wrg-sigma-smoke", "version": "1"},
                },
            )
        )
        read_response(1)
        send(_notification("notifications/initialized"))
        send(_request(2, "tools/list"))
        read_response(2)
        send(_request(3, "resources/list"))
        read_response(3)
    except (BrokenPipeError, OSError) as exc:
        proc.kill()
        return _fail(f"server closed the pipe early: {exc}")

    assert proc.stdin is not None
    proc.stdin.close()
    try:
        proc.wait(timeout=_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        proc.kill()
        return _fail(
            f"server did not exit within {_TIMEOUT_SECONDS}s of stdin closing"
        )

    stderr_text = proc.stderr.read() if proc.stderr else ""

    if 1 not in responses:
        return _fail("no response to initialize", stderr=stderr_text)
    init_result = responses[1].get("result") or {}
    server_name = (init_result.get("serverInfo") or {}).get("name")
    if not server_name:
        return _fail(
            "initialize response carried no serverInfo.name", stderr=stderr_text
        )

    if 2 not in responses:
        return _fail("no response to tools/list", stderr=stderr_text)
    tools = {
        tool.get("name")
        for tool in (responses[2].get("result") or {}).get("tools", [])
    }
    missing_tools = _EXPECTED_TOOLS - tools
    if missing_tools:
        return _fail(f"server did not announce tools: {sorted(missing_tools)}")

    if 3 not in responses:
        return _fail("no response to resources/list", stderr=stderr_text)
    resources = {
        resource.get("uri")
        for resource in (responses[3].get("result") or {}).get("resources", [])
    }
    missing_resources = _EXPECTED_RESOURCES - resources
    if missing_resources:
        return _fail(
            f"server did not announce resources: {sorted(missing_resources)}"
        )

    print(f"OK: {server_name} announced {len(tools)} tool(s), "
          f"{len(resources)} resource(s) over stdio")
    print(f"    tools:     {', '.join(sorted(tools))}")
    print(f"    resources: {', '.join(sorted(resources))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

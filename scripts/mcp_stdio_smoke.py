"""Smoke-test an MCP stdio server by actually speaking the protocol to it.

Takes the server command as arguments, so the same check covers both
surfaces this repo ships:

    python scripts/mcp_stdio_smoke.py python server.py
    python scripts/mcp_stdio_smoke.py docker run -i --rm wrg-sigma-rules-mcp
    python scripts/mcp_stdio_smoke.py --expect-corpus-fingerprint <sha256> -- \\
        docker run -i --rm wrg-sigma-rules-mcp

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
import queue
import re
# This explicit local/CI process harness needs subprocess; invocation below is
# an argv list with shell=False, never a shell command string.
import subprocess  # nosec B404
import sys
import threading
from pathlib import Path
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
_REPO_ROOT = Path(__file__).resolve().parent.parent
_PLUGIN_MANIFEST = _REPO_ROOT / ".claude-plugin" / "plugin.json"
_CORPUS_FINGERPRINT_RE = re.compile(
    r"^- Rules-content SHA-256: `[0-9a-f]{64}`$", re.MULTILINE
)

# Self-contained, deliberately minimal -- not a corpus file path, so renaming
# or removing a resources/examples/ rule can never break this smoke test for
# a reason unrelated to whether the server actually runs a tool.
_SMOKE_RULE_YAML = """\
title: Smoke-test rule (not a corpus rule)
id: 00000000-0000-0000-0000-000000000000
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\whoami.exe'
    condition: selection
falsepositives:
    - Legitimate use of whoami for diagnostics
level: low
"""


class _ResponseTimeout(TimeoutError):
    """The server did not answer one protocol request in the bounded window."""


def _coverage_corpus_fingerprint(contents: list[dict[str, Any]]) -> str | None:
    """Return the coverage resource's full corpus digest, if it has one."""
    for content in contents:
        if not isinstance(content, dict):
            continue
        text = content.get("text")
        if not isinstance(text, str):
            continue
        match = _CORPUS_FINGERPRINT_RE.search(text)
        if match:
            return match.group(0).split("`")[1]
    return None


def _has_coverage_corpus_identity(contents: list[dict[str, Any]]) -> bool:
    """Require the resource to identify the corpus behind its rollup."""
    return _coverage_corpus_fingerprint(contents) is not None


def _parse_command(argv: list[str]) -> tuple[str | None, list[str]]:
    """Parse the optional cross-surface identity check and server command."""
    expected_fingerprint: str | None = None
    if argv[:1] == ["--expect-corpus-fingerprint"]:
        if len(argv) < 2 or not re.fullmatch(r"[0-9a-f]{64}", argv[1]):
            raise ValueError(
                "--expect-corpus-fingerprint requires a lowercase 64-character SHA-256"
            )
        expected_fingerprint = argv[1]
        argv = argv[2:]
    if argv[:1] == ["--"]:
        argv = argv[1:]
    return expected_fingerprint, argv


def _expected_server_version(manifest: Path = _PLUGIN_MANIFEST) -> str:
    """Read the version the image/check-out server must announce."""
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("cannot read expected plugin version") from exc
    version = data.get("version") if isinstance(data, dict) else None
    if not isinstance(version, str) or not version.strip():
        raise ValueError("expected plugin version is missing or invalid")
    return version


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


def _protocol_message(line: str) -> dict[str, Any] | None:
    """Parse one stdout line, rejecting data that would corrupt stdio MCP."""
    line = line.strip()
    if not line:
        return None
    try:
        message = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError("stdout line is not valid JSON-RPC JSON") from exc
    if not isinstance(message, dict):
        raise ValueError("stdout JSON-RPC message is not an object")
    return message


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
    try:
        expected_fingerprint, argv = _parse_command(argv)
    except ValueError as exc:
        return _fail(str(exc))
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
            shell=False,  # nosec B603
        )
    except FileNotFoundError:
        return _fail(f"server command not found: {argv[0]}")

    # PIPE is requested above, but keep a real runtime check rather than an
    # assert: Python -O removes asserts and would turn a broken/mocked process
    # setup into an unrelated AttributeError inside a protocol exchange.
    if proc.stdin is None or proc.stdout is None:
        proc.kill()
        proc.wait()
        return _fail("server process did not provide required stdin/stdout pipes")
    stdin = proc.stdin
    stdout = proc.stdout

    responses: dict[int, dict[str, Any]] = {}
    protocol_violations: list[str] = []
    stdout_lines: queue.Queue[str | None] = queue.Queue()

    def pump_stdout() -> None:
        """Move blocking pipe reads off the request/response control path."""
        for line in stdout:
            stdout_lines.put(line)
        stdout_lines.put(None)

    stdout_thread = threading.Thread(target=pump_stdout, daemon=True)
    stdout_thread.start()

    def send(line: str) -> None:
        stdin.write(line + "\n")
        stdin.flush()

    def read_response(request_id: int) -> dict[str, Any] | None:
        """Read stdout until the reply to ``request_id`` arrives.

        The exchange is driven one request at a time rather than piping the
        whole conversation in at once: closing stdin immediately after the
        last request races the server, which can process it and exit before
        the reply is flushed. That race dropped the final response entirely
        when this script wrote everything up front.
        """
        while True:
            try:
                line = stdout_lines.get(timeout=_TIMEOUT_SECONDS)
            except queue.Empty as exc:
                raise _ResponseTimeout from exc
            if line is None:
                return None
            try:
                message = _protocol_message(line)
            except ValueError:
                protocol_violations.append(line.rstrip())
                continue
            if message is None:
                continue
            if isinstance(message.get("id"), int):
                responses[message["id"]] = message
                if message["id"] == request_id:
                    return message
        return None  # pragma: no cover - loop exits only on a response or EOF

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
        # R89 lesson from #57: a resource can ANNOUNCE itself in resources/list
        # and still fail the instant something tries to actually READ it (both
        # resources answered ok:false inside the Docker image while listing
        # worked fine outside it). Listing is not evidence of working; reading
        # and calling are.
        send(_request(4, "tools/call", {
            "name": "validate_rule",
            "arguments": {"yaml_content": _SMOKE_RULE_YAML},
        }))
        read_response(4)
        send(_request(5, "resources/read", {
            "uri": "wrg-sigma://coverage/mitre-attack-matrix",
        }))
        read_response(5)
    except _ResponseTimeout:
        proc.kill()
        proc.wait()
        return _fail(f"server did not reply within {_TIMEOUT_SECONDS}s")
    except (BrokenPipeError, OSError) as exc:
        proc.kill()
        proc.wait()
        return _fail(f"server closed the pipe early: {exc}")

    stdin.close()
    try:
        proc.wait(timeout=_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        proc.kill()
        return _fail(
            f"server did not exit within {_TIMEOUT_SECONDS}s of stdin closing"
        )

    stderr_text = proc.stderr.read() if proc.stderr else ""
    stdout_thread.join(timeout=_TIMEOUT_SECONDS)
    while True:
        try:
            line = stdout_lines.get_nowait()
        except queue.Empty:
            break
        if line is None:
            continue
        try:
            _protocol_message(line)
        except ValueError:
            protocol_violations.append(line.rstrip())

    if protocol_violations:
        return _fail(
            "server wrote non-protocol data to stdout",
            stdout="\n".join(protocol_violations),
            stderr=stderr_text,
        )

    if 1 not in responses:
        return _fail("no response to initialize", stderr=stderr_text)
    init_result = responses[1].get("result") or {}
    server_info = init_result.get("serverInfo") or {}
    server_name = server_info.get("name")
    if not server_name:
        return _fail(
            "initialize response carried no serverInfo.name", stderr=stderr_text
        )
    # The server used to advertise a bare name and no version at all, so a
    # client had no way to tell which corpus revision it was talking to.
    # This checks the live handshake, not just that server.py sets an
    # attribute somewhere.
    server_version = server_info.get("version")
    if not server_version:
        return _fail(
            "initialize response carried no serverInfo.version", stderr=stderr_text
        )
    try:
        expected_server_version = _expected_server_version()
    except ValueError as exc:
        return _fail(str(exc), stderr=stderr_text)
    if server_version != expected_server_version:
        return _fail(
            "server announced version "
            f"{server_version!r}, expected {expected_server_version!r}",
            stderr=stderr_text,
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

    if 4 not in responses:
        return _fail("no response to tools/call(validate_rule)", stderr=stderr_text)
    call_result = responses[4].get("result") or {}
    if call_result.get("isError"):
        return _fail(
            f"validate_rule tool call returned an error: {call_result}",
            stderr=stderr_text,
        )
    if "error" in responses[4]:
        return _fail(
            f"tools/call(validate_rule) failed: {responses[4]['error']}",
            stderr=stderr_text,
        )

    if 5 not in responses:
        return _fail("no response to resources/read(coverage matrix)", stderr=stderr_text)
    if "error" in responses[5]:
        return _fail(
            f"resources/read(coverage matrix) failed: {responses[5]['error']}",
            stderr=stderr_text,
        )
    read_result = responses[5].get("result") or {}
    contents = read_result.get("contents") or []
    if not contents or not any((c.get("text") or "").strip() for c in contents):
        return _fail(
            "resources/read(coverage matrix) returned no text content",
            stderr=stderr_text,
        )
    actual_fingerprint = _coverage_corpus_fingerprint(contents)
    if actual_fingerprint is None:
        return _fail(
            "resources/read(coverage matrix) omitted a valid corpus fingerprint",
            stderr=stderr_text,
        )
    if expected_fingerprint and actual_fingerprint != expected_fingerprint:
        return _fail(
            "coverage matrix fingerprint "
            f"{actual_fingerprint!r}, expected {expected_fingerprint!r}",
            stderr=stderr_text,
        )

    print(f"OK: {server_name} v{server_version} announced {len(tools)} tool(s), "
          f"{len(resources)} resource(s) over stdio")
    print(f"    tools:     {', '.join(sorted(tools))}")
    print(f"    resources: {', '.join(sorted(resources))}")
    print("    validate_rule tool call: ok")
    print(f"    coverage-matrix corpus SHA-256: {actual_fingerprint}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

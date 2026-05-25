# Glama-deployable MCP server image for wrg-sigma-rules.
#
# Glama runs automated safety/quality checks against the stdio MCP server
# this image exposes. The image is self-contained — all runtime deps come
# from PyPI via requirements.txt plus the `mcp` SDK installed inline below.
#
# Build:
#   docker build -t wrg-sigma-rules-mcp .
#
# Run (matches Glama's expected invocation; stdio MCP transport):
#   docker run -i --rm wrg-sigma-rules-mcp
#
# References:
#   https://glama.ai/mcp/servers (Glama MCP server catalog)
#   https://modelcontextprotocol.io/quickstart/server

FROM python:3.12-slim

# Glama best-practice: non-root user for MCP server runtime to limit
# blast radius if a malicious rule body somehow escapes interpreter scope.
RUN groupadd --system mcp && useradd --system --gid mcp --create-home mcp

WORKDIR /app

# Install plugin runtime deps (cache layer; rebuild only when reqs change).
# `mcp` SDK is installed inline rather than baked into requirements.txt so
# the Claude Code plugin runtime (which already provides MCP) is not forced
# to install a redundant copy.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir "mcp>=1.0"

# Copy server entrypoint + tool source. Skills/rules/tests/scripts excluded
# via .dockerignore — Glama runs the MCP server, not the Claude Code
# plugin surface.
COPY server.py .
COPY tools/ ./tools/

USER mcp

# stdio MCP server. -u: unbuffered stdout so Glama sees JSON-RPC frames
# immediately without Python's default block buffering.
ENTRYPOINT ["python", "-u", "server.py"]

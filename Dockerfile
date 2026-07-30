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
# `mcp` SDK is pinned in requirements.txt like every other runtime dep.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server entrypoint + tool source. Skills/tests/scripts stay out via
# .dockerignore — Glama runs the MCP server, not the Claude Code plugin
# surface.
COPY server.py .
COPY tools/ ./tools/

# resources/ is runtime data, not plugin surface. BOTH published resources
# read from it — the MITRE coverage matrix recomputes from resources/examples
# on every read, and the canonical-patterns resource reads
# resources/canonical-patterns/INDEX.md. Shipped without them the server still
# starts, still lists both, and answers each with ok:false: a degradation no
# build step can notice, which is why tests/test_image_contents.py derives
# this list from the code rather than trusting the comment above it.
COPY resources/ ./resources/

USER mcp

# stdio MCP server. -u: unbuffered stdout so Glama sees JSON-RPC frames
# immediately without Python's default block buffering.
ENTRYPOINT ["python", "-u", "server.py"]

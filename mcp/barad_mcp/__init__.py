"""MCP transport for Barad-dûr: the tool catalog with a different port.

The server is a renderer, not a second implementation — every tool it exposes is a
row in `backend.app.ai.tools`, which is also what the in-process executor runs. A tool
that exists here exists there, and the parameters cannot drift.
"""

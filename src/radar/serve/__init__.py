"""radar serve — live localhost dashboard (stdlib HTTP + SSE).

Public entry point is :func:`radar.serve.server.serve`.
"""

from radar.serve.server import serve

__all__ = ["serve"]

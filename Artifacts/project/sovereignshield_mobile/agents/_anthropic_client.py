"""Internal helper: Anthropic client constructor that neutralizes HF proxy env vars.

HuggingFace Spaces sets HTTP_PROXY / HTTPS_PROXY in the container environment.
httpx 0.28+ removed the legacy `proxies` keyword the Anthropic SDK relied on
when constructing its internal AsyncClient, which makes a bare `Anthropic()`
on HF raise:

    TypeError: AsyncClient.__init__() got an unexpected keyword argument 'proxies'

Wrapping an httpx.Client with trust_env=False and passing it as `http_client`
prevents the SDK from constructing its own proxy-aware client.

Pattern mirrors AuditShield app_config.get_anthropic_client (commit 5a8432a).
"""

from __future__ import annotations

import os


def get_anthropic_client():
    """Return an Anthropic client that ignores container proxy env vars."""
    import httpx
    from anthropic import Anthropic

    api_key = os.getenv("ANTHROPIC_API_KEY")
    http_client = httpx.Client(trust_env=False)
    return Anthropic(api_key=api_key, http_client=http_client)

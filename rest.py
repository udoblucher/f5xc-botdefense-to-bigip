#!/usr/bin/env python3
"""rest.py -- minimal HTTP client shared by the XC and BIG-IP clients.

Python standard library only (urllib, not requests), so every module here also
runs on a stock BIG-IP where python3 is present but requests is not.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from typing import Any


class HTTPError(RuntimeError):
    """Non-2xx HTTP response. Carries the status and the (truncated) body."""

    def __init__(self, status: int, url: str, body: str):
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status} for {url}: {body[:400]}")


def _ctx(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:                      # BIG-IP default cert is self-signed
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def request(method: str, url: str, *, headers: dict | None = None,
            data: bytes | None = None, auth: tuple[str, str] | None = None,
            verify: bool = True, timeout: int = 30) -> tuple[int, bytes]:
    """One HTTP request -> (status, body_bytes).

    `auth` adds a Basic header in-process, so the credential never reaches the
    process table. Raises HTTPError on 4xx/5xx.
    """
    hdrs = dict(headers or {})
    if auth is not None:
        blob = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        hdrs["Authorization"] = f"Basic {blob}"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_ctx(verify)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace") if e.fp else ""
        raise HTTPError(e.code, url, body) from None


def request_json(method: str, url: str, *, headers: dict | None = None,
                 obj: Any = None, auth: tuple[str, str] | None = None,
                 verify: bool = True, timeout: int = 30) -> Any:
    """request() with JSON in and JSON out. Empty or non-JSON body -> {}."""
    hdrs = dict(headers or {})
    body = None
    if obj is not None:
        body = json.dumps(obj).encode()
        hdrs.setdefault("Content-Type", "application/json")
    _, raw = request(method, url, headers=hdrs, data=body, auth=auth,
                     verify=verify, timeout=timeout)
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}

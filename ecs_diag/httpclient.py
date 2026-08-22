"""Minimal JSON-over-HTTP helper built on urllib, so no third-party HTTP client is needed."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional


class HttpError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


def request_json(
    url: str,
    *,
    method: str = "GET",
    params: Optional[dict[str, Any]] = None,
    data: Optional[dict[str, Any]] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: float = 30.0,
    verify_tls: bool = True,
    bearer_token: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> Any:
    """Perform a request and decode the JSON body, raising HttpError on failure."""
    if params:
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}, doseq=True)
        url = f"{url}{'&' if '?' in url else '?'}{query}"

    body: Optional[bytes] = None
    request_headers = {"Accept": "application/json"}
    if data is not None:
        body = urllib.parse.urlencode(data, doseq=True).encode()
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
    if bearer_token:
        request_headers["Authorization"] = f"Bearer {bearer_token}"
    elif username is not None and password is not None:
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        request_headers["Authorization"] = f"Basic {credentials}"
    request_headers.update(headers or {})

    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    context = None
    if url.lower().startswith("https") and not verify_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise HttpError(f"HTTP {exc.code} from {url}: {detail}", status=exc.code, body=detail) from exc
    except urllib.error.URLError as exc:
        raise HttpError(f"could not reach {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise HttpError(f"timed out after {timeout}s calling {url}") from exc

    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HttpError(f"non-JSON response from {url}: {raw[:200]}") from exc


def join_url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}/{path.lstrip('/')}"

"""Base HTTP client with safety controls for all platform integrations.

Every platform client inherits from this. It enforces:
- HTTPS-only connections
- Redirect rejection
- Response size limits
- Request/response audit logging
- Credential isolation (env vars only)
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

try:
    from ..common import ROOT, audit, sha256_file, utc_now
except ImportError:
    from common import ROOT, audit, sha256_file, utc_now


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError(f"Platform attempted an unexpected redirect: {newurl}")


class PlatformClient:
    """Base client for HTTPS platform APIs with safety controls."""

    MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MiB

    def __init__(
        self,
        base_url: str,
        platform_name: str,
        ca_file: str | None = None,
        timeout: int = 30,
    ):
        self.base_url = self._validate_base_url(base_url)
        self.platform_name = platform_name
        self.timeout = timeout
        self._ssl_context = ssl.create_default_context(
            cafile=ca_file,
        )

    def _validate_base_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https":
            raise RuntimeError(f"Platform base_url must be HTTPS: {url}")
        if not parsed.hostname:
            raise RuntimeError(f"Platform base_url has no hostname: {url}")
        if parsed.username or parsed.password:
            raise RuntimeError(f"Platform base_url must not contain embedded credentials: {url}")
        return url.rstrip("/")

    def _get_env(self, name: str) -> str:
        value = os.environ.get(name)
        if not value:
            raise RuntimeError(
                f"Required environment variable is not set: {name}. "
                f"Set it in your shell or in config/platforms.toml."
            )
        return value

    def _build_headers(self, **extra: str) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "ai-soc-operator/1.0",
        }
        headers.update(extra)
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any] | str:
        url = f"{self.base_url}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query, doseq=True)

        data = json.dumps(body).encode("utf-8") if body else None
        request_headers = self._build_headers**(headers or {})
        if body:
            request_headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            url,
            data=data,
            headers=request_headers,
            method=method,
        )

        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ssl_context),
            NoRedirect(),
        )

        audit(
            "platform_request_started",
            platform=self.platform_name,
            method=method,
            path=path,
        )

        try:
            with opener.open(request, timeout=self.timeout) as response:
                raw = response.read(self.MAX_RESPONSE_SIZE + 1)
                if len(raw) > self.MAX_RESPONSE_SIZE:
                    raise RuntimeError(
                        f"{self.platform_name} response exceeded {self.MAX_RESPONSE_SIZE} byte limit."
                    )
                status = response.status
        except urllib.error.HTTPError as error:
            audit(
                "platform_request_failed",
                platform=self.platform_name,
                method=method,
                path=path,
                status=error.code,
            )
            raise RuntimeError(
                f"{self.platform_name} returned HTTP {error.code}: {error.reason}"
            ) from error

        audit(
            "platform_request_finished",
            platform=self.platform_name,
            method=method,
            path=path,
            status=status,
        )

        if not raw:
            return {}

        content_type = ""
        for header_key in ("Content-Type", "content-type"):
            if header_key in (response.headers or {}):
                content_type = response.headers[header_key]
                break

        if "application/json" in content_type:
            return json.loads(raw.decode("utf-8"))
        return raw.decode("utf-8", errors="replace")

    def get(self, path: str, **kwargs: Any) -> Any:
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        return self._request("POST", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> Any:
        return self._request("PATCH", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> Any:
        return self._request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Any:
        return self._request("DELETE", path, **kwargs)

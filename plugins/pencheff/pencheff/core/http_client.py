"""Shared async HTTP client with credential injection, rate limiting, and logging."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from pencheff.config import DEFAULT_REQUEST_TIMEOUT, MAX_REQUESTS_PER_SECOND, MAX_RESPONSE_SIZE
from pencheff.core.credentials import CredentialSet
from pencheff.core.session import PentestSession


class PencheffHTTPClient:
    """Async HTTP client wrapper for pentest operations."""

    def __init__(
        self,
        session: PentestSession,
        credential_set: str = "default",
        verify_ssl: bool = False,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
        max_rps: float = MAX_REQUESTS_PER_SECOND,
    ):
        self.session = session
        self._cred_name = credential_set
        self._verify_ssl = verify_ssl
        self._timeout = timeout
        self._max_rps = max_rps
        self._min_interval = 1.0 / max_rps if max_rps > 0 else 0
        self._last_request_time = 0.0
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=self._verify_ssl,
                timeout=httpx.Timeout(self._timeout),
                follow_redirects=True,
                max_redirects=5,
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            )
        return self._client

    def _get_creds(self) -> CredentialSet | None:
        return self.session.credentials.get(self._cred_name)

    async def _rate_limit(self):
        if self._min_interval > 0:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_request_time = time.monotonic()

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        json_data: Any = None,
        params: dict[str, str] | None = None,
        follow_redirects: bool = True,
        inject_creds: bool = True,
        module: str = "unknown",
    ) -> httpx.Response:
        await self._rate_limit()
        client = await self._get_client()

        req_headers = dict(headers or {})
        req_headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; PencheffScanner/0.1)")

        if inject_creds:
            creds = self._get_creds()
            if creds:
                req_headers = creds.inject_into_headers(req_headers)

        start = time.monotonic()
        kwargs: dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": req_headers,
            "follow_redirects": follow_redirects,
        }
        if body is not None:
            kwargs["content"] = body
        if json_data is not None:
            kwargs["json"] = json_data
        if params:
            kwargs["params"] = params

        try:
            response = await client.request(**kwargs)
            duration_ms = (time.monotonic() - start) * 1000
            self.session.log_request(method, url, response.status_code, module, duration_ms)
            return response
        except httpx.HTTPError as e:
            duration_ms = (time.monotonic() - start) * 1000
            self.session.log_request(method, url, None, module, duration_ms)
            raise

    async def get(self, url: str, module: str = "unknown", **kwargs) -> httpx.Response:
        return await self.request("GET", url, module=module, **kwargs)

    async def post(self, url: str, module: str = "unknown", **kwargs) -> httpx.Response:
        return await self.request("POST", url, module=module, **kwargs)

    async def put(self, url: str, module: str = "unknown", **kwargs) -> httpx.Response:
        return await self.request("PUT", url, module=module, **kwargs)

    async def delete(self, url: str, module: str = "unknown", **kwargs) -> httpx.Response:
        return await self.request("DELETE", url, module=module, **kwargs)

    async def options(self, url: str, module: str = "unknown", **kwargs) -> httpx.Response:
        return await self.request("OPTIONS", url, module=module, **kwargs)

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

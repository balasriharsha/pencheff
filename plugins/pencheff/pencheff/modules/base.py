"""Base class for all testing modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pencheff.core.findings import Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession


class BaseTestModule(ABC):
    """Abstract base for pentest testing modules."""

    name: str = ""
    category: str = ""
    owasp_categories: list[str] = []
    description: str = ""

    @abstractmethod
    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Execute this module's tests. Returns a list of findings."""
        ...

    @abstractmethod
    def get_techniques(self) -> list[str]:
        """Return list of technique names this module can run."""
        ...

    def _get_target_endpoints(
        self, session: PentestSession, targets: list[str] | None
    ) -> list[dict[str, Any]]:
        """Get endpoints to test — either explicit targets or all discovered."""
        if targets:
            return [{"url": t, "method": "GET", "params": []} for t in targets]
        return session.discovered.endpoints or [
            {"url": session.target.base_url, "method": "GET", "params": []}
        ]

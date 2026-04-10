"""Pentest session state management."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pencheff.config import TestDepth
from pencheff.core.credentials import CredentialStore
from pencheff.core.findings import FindingsDB


@dataclass
class RequestRecord:
    """Audit trail entry for an HTTP request."""

    method: str
    url: str
    status: int | None
    timestamp: datetime
    module: str
    duration_ms: float = 0.0


@dataclass
class TargetInfo:
    """Information about the pentest target."""

    base_url: str
    scope: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)


@dataclass
class DiscoveredState:
    """Dynamic state discovered during testing."""

    endpoints: list[dict[str, Any]] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    tech_stack: dict[str, list[str]] = field(default_factory=dict)
    api_specs: list[dict[str, Any]] = field(default_factory=list)
    completed_modules: list[str] = field(default_factory=list)
    running_module: str | None = None
    # Advanced discovery state
    websocket_endpoints: list[dict[str, Any]] = field(default_factory=list)
    oauth_endpoints: list[dict[str, Any]] = field(default_factory=list)
    waf_detected: dict[str, Any] = field(default_factory=dict)
    exploit_chains: list[dict[str, Any]] = field(default_factory=list)
    cname_records: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PentestSession:
    """Central state object for a penetration test."""

    id: str
    target: TargetInfo
    credentials: CredentialStore
    depth: TestDepth
    findings: FindingsDB
    discovered: DiscoveredState
    request_log: list[RequestRecord] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def log_request(self, method: str, url: str, status: int | None, module: str, duration_ms: float = 0.0):
        self.request_log.append(RequestRecord(
            method=method, url=url, status=status,
            timestamp=datetime.now(timezone.utc),
            module=module, duration_ms=duration_ms,
        ))

    def status_summary(self) -> dict[str, Any]:
        return {
            "session_id": self.id,
            "target": self.target.base_url,
            "depth": self.depth.value,
            "credentials": self.credentials.count,
            "endpoints_discovered": len(self.discovered.endpoints),
            "subdomains_discovered": len(self.discovered.subdomains),
            "open_ports": len(self.discovered.open_ports),
            "tech_stack": self.discovered.tech_stack,
            "completed_modules": self.discovered.completed_modules,
            "running_module": self.discovered.running_module,
            "findings": self.findings.summary(),
            "total_findings": self.findings.count,
            "total_requests": len(self.request_log),
            "websocket_endpoints": len(self.discovered.websocket_endpoints),
            "oauth_endpoints": len(self.discovered.oauth_endpoints),
            "waf_detected": self.discovered.waf_detected or None,
            "exploit_chains": len(self.discovered.exploit_chains),
        }


# In-process session store (one per Claude Code session)
_sessions: dict[str, PentestSession] = {}


def create_session(
    target_url: str,
    credentials: dict[str, Any] | None = None,
    scope: list[str] | None = None,
    exclude_paths: list[str] | None = None,
    depth: str = "standard",
) -> PentestSession:
    session_id = uuid.uuid4().hex[:12]
    cred_store = CredentialStore()
    if credentials:
        cred_store.add_from_dict("default", credentials)

    target = TargetInfo(
        base_url=target_url.rstrip("/"),
        scope=scope or [target_url],
        exclude_paths=exclude_paths or [],
    )

    session = PentestSession(
        id=session_id,
        target=target,
        credentials=cred_store,
        depth=TestDepth(depth),
        findings=FindingsDB(),
        discovered=DiscoveredState(),
    )
    _sessions[session_id] = session
    return session


def get_session(session_id: str) -> PentestSession | None:
    return _sessions.get(session_id)

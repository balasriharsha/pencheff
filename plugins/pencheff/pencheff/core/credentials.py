"""Secure credential management — never logged, never returned in findings."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any


class MaskedSecret:
    """A string value that masks itself in repr/str to prevent accidental leakage."""

    def __init__(self, value: str):
        self._value = value

    def get(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "MaskedSecret(****)"

    def __str__(self) -> str:
        return "****"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MaskedSecret):
            return self._value == other._value
        return False


@dataclass
class CredentialSet:
    """A named set of credentials for one user/role."""

    name: str
    username: MaskedSecret | None = None
    password: MaskedSecret | None = None
    api_key: MaskedSecret | None = None
    token: MaskedSecret | None = None
    cookie: MaskedSecret | None = None
    custom_headers: dict[str, MaskedSecret] = field(default_factory=dict)

    def get_basic_auth(self) -> str | None:
        if self.username and self.password:
            raw = f"{self.username.get()}:{self.password.get()}"
            return f"Basic {base64.b64encode(raw.encode()).decode()}"
        return None

    def get_bearer_token(self) -> str | None:
        if self.token:
            return f"Bearer {self.token.get()}"
        return None

    def inject_into_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Inject credentials into request headers."""
        headers = dict(headers)
        if self.token:
            headers["Authorization"] = self.get_bearer_token()
        elif self.username and self.password:
            headers["Authorization"] = self.get_basic_auth()
        if self.api_key:
            headers["X-API-Key"] = self.api_key.get()
        if self.cookie:
            headers["Cookie"] = self.cookie.get()
        for key, val in self.custom_headers.items():
            headers[key] = val.get()
        return headers


class CredentialStore:
    """Stores multiple credential sets for a pentest session."""

    def __init__(self):
        self._sets: dict[str, CredentialSet] = {}

    def add_from_dict(self, name: str, creds: dict[str, Any]) -> CredentialSet:
        cs = CredentialSet(
            name=name,
            username=MaskedSecret(creds["username"]) if "username" in creds else None,
            password=MaskedSecret(creds["password"]) if "password" in creds else None,
            api_key=MaskedSecret(creds["api_key"]) if "api_key" in creds else None,
            token=MaskedSecret(creds["token"]) if "token" in creds else None,
            cookie=MaskedSecret(creds["cookie"]) if "cookie" in creds else None,
            custom_headers={
                k: MaskedSecret(v)
                for k, v in creds.get("custom_headers", {}).items()
            },
        )
        self._sets[name] = cs
        return cs

    def get(self, name: str = "default") -> CredentialSet | None:
        return self._sets.get(name)

    def get_all(self) -> dict[str, CredentialSet]:
        return dict(self._sets)

    @property
    def count(self) -> int:
        return len(self._sets)

    def __repr__(self) -> str:
        return f"CredentialStore(sets={list(self._sets.keys())})"

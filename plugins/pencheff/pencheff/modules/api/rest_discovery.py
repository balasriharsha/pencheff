"""REST API discovery — OpenAPI/Swagger spec detection, route enumeration."""

from __future__ import annotations

import json
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

SPEC_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
    "/openapi.json", "/openapi.yaml", "/v1/api-docs", "/v2/api-docs",
    "/v3/api-docs", "/api/swagger.json", "/api/openapi.json",
    "/docs", "/redoc", "/_catalog", "/api/v1/swagger.json",
    "/swagger-ui.html", "/swagger-ui/", "/graphql", "/graphiql",
]


class RestDiscoveryModule(BaseTestModule):
    name = "rest_discovery"
    category = "recon"
    owasp_categories = ["A05"]
    description = "REST API endpoint and spec discovery"

    def get_techniques(self) -> list[str]:
        return ["swagger_detection", "openapi_parsing", "graphql_detection"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url

        for path in SPEC_PATHS:
            try:
                resp = await http.get(
                    f"{base_url}{path}",
                    module="rest_discovery",
                    inject_creds=False,
                )
                if resp.status_code != 200:
                    continue

                content_type = resp.headers.get("content-type", "")

                # Check for Swagger/OpenAPI
                if "json" in content_type or path.endswith(".json"):
                    try:
                        spec = resp.json()
                        if "swagger" in spec or "openapi" in spec:
                            session.discovered.api_specs.append({
                                "type": "openapi",
                                "url": f"{base_url}{path}",
                                "version": spec.get("openapi", spec.get("swagger", "unknown")),
                            })

                            # Extract endpoints from spec
                            paths = spec.get("paths", {})
                            for api_path, methods in paths.items():
                                for method, details in methods.items():
                                    if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                                        params = []
                                        for p in details.get("parameters", []):
                                            params.append(p.get("name", ""))
                                        session.discovered.endpoints.append({
                                            "url": f"{base_url}{api_path}",
                                            "method": method.upper(),
                                            "source": "openapi",
                                            "params": params,
                                        })

                            findings.append(Finding(
                                title=f"API Specification Publicly Accessible: {path}",
                                severity=Severity.LOW,
                                category="misconfiguration",
                                owasp_category="A05",
                                description=f"OpenAPI/Swagger spec found at {path} with "
                                            f"{len(paths)} endpoints. Unauthenticated access to API docs "
                                            "reveals the full attack surface.",
                                remediation="Restrict API documentation to authenticated users or internal networks.",
                                endpoint=f"{base_url}{path}",
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                cvss_score=5.3,
                                cwe_id="CWE-200",
                            ))
                    except (json.JSONDecodeError, KeyError):
                        pass

                # Check for GraphQL
                if "graphql" in path.lower():
                    # Try introspection query
                    introspection = {
                        "query": '{ __schema { types { name } } }'
                    }
                    try:
                        gql_resp = await http.post(
                            f"{base_url}{path}",
                            json_data=introspection,
                            module="rest_discovery",
                        )
                        if gql_resp.status_code == 200 and "__schema" in gql_resp.text:
                            session.discovered.api_specs.append({
                                "type": "graphql",
                                "url": f"{base_url}{path}",
                                "introspection": True,
                            })
                            session.discovered.endpoints.append({
                                "url": f"{base_url}{path}",
                                "method": "POST",
                                "source": "graphql",
                                "params": ["query"],
                            })
                    except Exception:
                        pass

            except Exception:
                continue

        return findings

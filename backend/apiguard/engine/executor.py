import time
import uuid
import re
from typing import Dict, Any, Optional, Set
from urllib.parse import urlparse
import httpx
from apiguard.engine.models import PlanStep, ExecutionResult

class SecurityViolationError(Exception):
    pass

class SafeExecutor:
    """
    The ONLY module in APIGuard that sends HTTP requests.
    Enforces host allowlists, request budgets, rate limiting, and secret redaction.
    """
    def __init__(
        self,
        allowed_hosts: Optional[Set[str]] = None,
        total_budget: int = 50,
        per_endpoint_budget: int = 6,
        timeout_seconds: float = 5.0,
        max_response_bytes: int = 500_000,
        enable_mutations: bool = False
    ):
        self.allowed_hosts = allowed_hosts or {"localhost", "127.0.0.1"}
        self.total_budget = total_budget
        self.per_endpoint_budget = per_endpoint_budget
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.enable_mutations = enable_mutations

        self.requests_sent = 0
        self.endpoint_counts: Dict[str, int] = {}

    def sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        sanitized = {}
        for k, v in headers.items():
            k_lower = k.lower()
            if any(secret in k_lower for secret in ["authorization", "cookie", "token", "password", "api-key", "secret"]):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = v
        return sanitized

    def _validate_safety(self, step: PlanStep):
        # 1. Host allowlist check
        parsed = urlparse(step.url)
        hostname = (parsed.hostname or "").lower()
        if hostname not in self.allowed_hosts:
            raise SecurityViolationError(f"Host '{hostname}' is not in the allowlist {self.allowed_hosts}")

        # 2. Method safety
        allowed_post = step.method == "POST" and step.purpose in {"setup", "probe_mass_assignment"}
        if step.method in {"POST", "PUT", "PATCH", "DELETE"} and not self.enable_mutations and not allowed_post:
            raise SecurityViolationError(f"Mutating method {step.method} refused because mutations are disabled")

        # 3. Budget checks
        if self.requests_sent >= self.total_budget:
            raise SecurityViolationError(f"Total request budget of {self.total_budget} exceeded")

        ep_count = self.endpoint_counts.get(step.operation_id, 0)
        if ep_count >= self.per_endpoint_budget:
            raise SecurityViolationError(f"Per-endpoint budget of {self.per_endpoint_budget} exceeded for {step.operation_id}")

    async def execute_step(
        self,
        step: PlanStep,
        client: Optional[httpx.AsyncClient] = None
    ) -> ExecutionResult:
        self._validate_safety(step)

        correlation_id = f"corr_{uuid.uuid4().hex[:8]}"
        start_time = time.perf_counter()

        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=False)
            should_close = True

        try:
            self.requests_sent += 1
            self.endpoint_counts[step.operation_id] = self.endpoint_counts.get(step.operation_id, 0) + 1

            response = await client.request(
                method=step.method,
                url=step.url,
                headers=step.headers,
                json=step.json_body
            )

            duration = (time.perf_counter() - start_time) * 1000.0

            # Max size guard
            if len(response.content) > self.max_response_bytes:
                raise SecurityViolationError(f"Response size {len(response.content)} exceeded max limit {self.max_response_bytes}")

            try:
                body_json = response.json()
            except Exception:
                body_json = response.text

            return ExecutionResult(
                step_id=step.step_id,
                operation_id=step.operation_id,
                identity_id=step.identity_id,
                method=step.method,
                url=step.url,
                status_code=response.status_code,
                duration_ms=round(duration, 2),
                sanitized_headers=self.sanitize_headers(dict(response.headers)),
                body=body_json,
                correlation_id=correlation_id
            )

        except Exception as e:
            duration = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                step_id=step.step_id,
                operation_id=step.operation_id,
                identity_id=step.identity_id,
                method=step.method,
                url=step.url,
                status_code=0,
                duration_ms=round(duration, 2),
                sanitized_headers={},
                body=None,
                correlation_id=correlation_id,
                error=str(e)
            )
        finally:
            if should_close:
                await client.aclose()

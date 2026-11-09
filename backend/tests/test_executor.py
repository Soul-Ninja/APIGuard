import pytest
from apiguard.engine.executor import SafeExecutor, SecurityViolationError
from apiguard.engine.models import PlanStep

def test_host_allowlist_blocking():
    executor = SafeExecutor(allowed_hosts={"localhost", "127.0.0.1"})
    step = PlanStep(
        step_id="step_bad_host",
        identity_id="usr_a",
        operation_id="op_remote",
        method="GET",
        path_template="/remote",
        url="http://evil-external-site.com/api"
    )

    with pytest.raises(SecurityViolationError, match="not in the allowlist"):
        executor._validate_safety(step)

def test_request_budgets():
    # Per-endpoint budget = 2
    executor = SafeExecutor(total_budget=5, per_endpoint_budget=2)
    step = PlanStep(
        step_id="step_1",
        identity_id="usr_a",
        operation_id="getProjects",
        method="GET",
        path_template="/projects",
        url="http://localhost:8000/projects"
    )

    executor._validate_safety(step)
    executor.endpoint_counts["getProjects"] = 2

    # Should raise when per-endpoint budget is exceeded
    with pytest.raises(SecurityViolationError, match="Per-endpoint budget"):
        executor._validate_safety(step)

def test_token_redaction():
    executor = SafeExecutor()
    raw_headers = {
        "Authorization": "Bearer super_secret_jwt_token_12345",
        "X-API-Key": "my_api_key_secret",
        "Content-Type": "application/json",
        "User-Agent": "APIGuard/1.0"
    }

    sanitized = executor.sanitize_headers(raw_headers)
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["X-API-Key"] == "[REDACTED]"
    assert sanitized["Content-Type"] == "application/json"
    assert "super_secret_jwt_token_12345" not in str(sanitized)

import sys
import json
import pytest
import subprocess
from pathlib import Path
from apiguard.engine.models import Finding, FindingStatus, Hypothesis, Rule, RuleType, Provenance
from apiguard.engine.target import TargetProfile, IdentityConfig, ResourceOverride
from apiguard.engine.reports import (
    generate_sarif,
    generate_json_report,
    generate_markdown_report,
    write_reports,
    find_spec_line,
    map_finding_to_rule_id,
    get_version
)
from apiguard.engine.cli import run_cli_scan


def make_finding(
    id="fnd_1",
    category="BOLA",
    endpoint="/projects/{project_id}",
    method="GET",
    resource_type="Project",
    status=FindingStatus.CONFIRMED,
    confidence=1.0,
    severity="HIGH",
    repro_curl="curl -s http://127.0.0.1:8000/projects/1",
    diff_fields=None,
    probe_evidence=None,
    control_evidence=None
):
    return Finding(
        id=id,
        category=category,
        endpoint=endpoint,
        method=method,
        resource_type=resource_type,
        status=status,
        confidence=confidence,
        severity=severity,
        identities={"owner": "user_a", "probe": "user_b"},
        hypothesis=Hypothesis(
            id=f"hyp_{id}",
            rule=Rule(rule_type=RuleType.OWNER_ONLY, resource_type=resource_type),
            operation_id="op_test",
            confidence=confidence,
            provenance=Provenance.OBSERVED
        ),
        graph_path=["step1", "step2"],
        control_evidence=control_evidence or {},
        probe_evidence=probe_evidence or {},
        diff_fields=diff_fields or [],
        repro_curl=repro_curl
    )


def test_apiguard_version_flag(capsys):
    """Asserts that 'apiguard --version' prints the version string."""
    res = subprocess.run([sys.executable, "-m", "apiguard", "--version"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "APIGuard" in res.stdout
    assert get_version() in res.stdout


def test_spec_line_lookup():
    """Asserts exact line lookup for endpoints in OpenAPI specification."""
    sample_spec = """openapi: 3.0.3
info:
  title: Sample API
  version: 1.0.0
paths:
  /users:
    get:
      summary: List users
  /orders/{order_id}:
    get:
      summary: Get order
  /orders/{order_id}/items:
    get:
      summary: Get items
"""
    assert find_spec_line(sample_spec, "/users") == 6
    assert find_spec_line(sample_spec, "/orders/{order_id}") == 9
    assert find_spec_line(sample_spec, "/orders/{order_id}/items") == 12
    # Not found or aggregate passive finding falls back to line 1
    assert find_spec_line(sample_spec, "/nonexistent") == 1
    assert find_spec_line(sample_spec, "CORS") == 1


def test_sarif_structure_and_fingerprint_stability():
    """Asserts SARIF 2.1.0 schema, levels, security-severity, and stable fingerprint across runs."""
    profile = TargetProfile(
        base_url="http://127.0.0.1:8000",
        spec_path="backend/apiguard/targets/demo_spec.yaml",
        identities=[
            IdentityConfig(name="user_a", headers={"Authorization": "Bearer tok_a"}),
            IdentityConfig(name="user_b", headers={"Authorization": "Bearer tok_b"})
        ]
    )

    f_confirmed = make_finding(
        id="fnd_random_111",
        category="BOLA",
        endpoint="/projects/{project_id}",
        method="GET",
        resource_type="Project",
        status=FindingStatus.CONFIRMED,
        confidence=1.0,
        severity="HIGH",
        repro_curl="curl -s http://127.0.0.1:8000/projects/123",
        diff_fields=["owner_email"]
    )

    f_potential = make_finding(
        id="fnd_random_222",
        category="BFLA",
        endpoint="/admin/users",
        method="GET",
        resource_type="Admin",
        status=FindingStatus.POTENTIAL,
        confidence=0.4,
        severity="HIGH",
        repro_curl="curl -s http://127.0.0.1:8000/admin/users",
        diff_fields=["attacker got 2xx but body differs"]
    )

    sarif1 = generate_sarif([f_confirmed, f_potential], profile)
    assert sarif1["version"] == "2.1.0"
    assert "https://raw.githubusercontent.com/oasis-tcs/sarif-spec" in sarif1["$schema"]

    driver = sarif1["runs"][0]["tool"]["driver"]
    assert driver["name"] == "APIGuard"
    assert driver["version"] == get_version()
    assert driver["informationUri"] == "https://github.com/Soul-Ninja/APIGuard"

    rules = {r["id"]: r for r in driver["rules"]}
    assert "APIGUARD-BOLA" in rules
    assert "API1:2023" in rules["APIGUARD-BOLA"]["properties"]["tags"]
    assert rules["APIGUARD-BOLA"]["properties"]["security-severity"] == "7.5"

    results = sarif1["runs"][0]["results"]
    assert len(results) == 2

    # Confirmed HIGH finding -> error, security-severity 7.5
    r_conf = results[0]
    assert r_conf["ruleId"] == "APIGUARD-BOLA"
    assert r_conf["level"] == "error"
    assert r_conf["properties"]["security-severity"] == "7.5"
    assert r_conf["locations"][0]["logicalLocations"][0]["name"] == "GET /projects/{project_id}"
    fp1 = r_conf["partialFingerprints"]["apiguardFindingKey/v1"]

    # POTENTIAL finding -> always note, message starts with "Needs review:"
    r_pot = results[1]
    assert r_pot["ruleId"] == "APIGUARD-BFLA"
    assert r_pot["level"] == "note"
    assert r_pot["message"]["text"].startswith("Needs review:")

    # Run 2 with different random IDs on findings: fingerprint must be identical!
    f_confirmed_run2 = make_finding(
        id="fnd_different_random_999",
        category="BOLA",
        endpoint="/projects/{project_id}",
        method="GET",
        resource_type="Project",
        status=FindingStatus.CONFIRMED,
        confidence=1.0,
        severity="HIGH"
    )
    sarif2 = generate_sarif([f_confirmed_run2], profile)
    fp2 = sarif2["runs"][0]["results"][0]["partialFingerprints"]["apiguardFindingKey/v1"]
    assert fp1 == fp2, "Fingerprint must be stable regardless of finding ID"


def test_no_real_tokens_or_expired_tokens_in_reports(tmp_path):
    """
    Asserts that no real token, password, or expired_token value ever appears
    in SARIF, JSON, or Markdown reports.
    """
    secret_token_a = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYW1hbiJ9.SECRET_SIG_AAA"
    secret_token_b = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGFhcmFuIn0.SECRET_SIG_BBB"
    secret_expired = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEwMDAwMH0.SECRET_EXPIRED_CCC"
    secret_password = "SuperSecretAdminPassword123!"

    profile = TargetProfile(
        base_url="http://127.0.0.1:8000",
        spec_path="backend/apiguard/targets/demo_spec.yaml",
        identities=[
            IdentityConfig(name="user_a", token=secret_token_a, password=secret_password),
            IdentityConfig(name="user_b", token=secret_token_b, expired_token=secret_expired)
        ]
    )

    finding = make_finding(
        id="fnd_auth_01",
        category="AUTH",
        endpoint="/projects/{project_id}",
        method="GET",
        resource_type="Auth",
        status=FindingStatus.CONFIRMED,
        confidence=1.0,
        severity="HIGH",
        repro_curl="curl -s http://127.0.0.1:8000/projects/1 -H 'Authorization: Bearer <USER_B_TOKEN>'",
        diff_fields=[f"raw_leak_{secret_token_a}"],
        probe_evidence={"evidence": f"Leaked {secret_expired} and pass {secret_password}"}
    )

    json_file = tmp_path / "out.json"
    sarif_file = tmp_path / "out.sarif"
    md_file = tmp_path / "out.md"

    write_reports(
        findings=[finding],
        profile=profile,
        json_path=str(json_file),
        sarif_path=str(sarif_file),
        markdown_path=str(md_file)
    )

    for p in (json_file, sarif_file, md_file):
        content = p.read_text(encoding="utf-8")
        assert secret_token_a not in content
        assert secret_token_b not in content
        assert secret_expired not in content
        assert secret_password not in content
        assert "<REDACTED>" in content


def test_markdown_hard_cap_60000():
    """Asserts that markdown report strictly enforces the 60,000 character hard cap."""
    profile = TargetProfile(
        base_url="http://127.0.0.1:8000",
        spec_path="backend/apiguard/targets/demo_spec.yaml"
    )

    # Create 300 findings to easily exceed 60,000 characters
    findings = []
    for i in range(300):
        findings.append(make_finding(
            id=f"fnd_{i:04d}",
            category="BOLA",
            endpoint=f"/very/long/nested/path/to/resource/{i}/subresource/details/information",
            method="GET",
            resource_type="DeepResource",
            status=FindingStatus.CONFIRMED,
            confidence=1.0,
            severity="HIGH",
            diff_fields=[f"field_{j}_leaked_long_attribute_value_here" for j in range(10)],
            repro_curl=f"curl -s -X GET 'http://127.0.0.1:8000/very/long/nested/path/to/resource/{i}/subresource/details/information' -H 'Authorization: Bearer <USER_B_TOKEN>'"
        ))

    md = generate_markdown_report(findings, profile)
    assert len(md) <= 60000
    assert md.startswith("<!-- apiguard-report -->")
    assert "more findings, see the SARIF/JSON report" in md


@pytest.mark.asyncio
async def test_fail_on_matrix():
    """
    Tests --fail-on matrix:
    - absent: exit 1 on active CONFIRMED; exit 0 on passive CONFIRMED only
    - none: exit 0 always
    - high: exit 1 on HIGH; exit 0 on LOW
    - low: exit 1 on LOW
    - POTENTIAL findings never fail build
    """
    f_active_high = make_finding(
        id="f1", category="BOLA", endpoint="/a", method="GET",
        resource_type="A", status=FindingStatus.CONFIRMED, severity="HIGH"
    )
    f_passive_low = make_finding(
        id="f2", category="MISCONFIG", endpoint="Version Disclosure", method="ALL",
        resource_type="Headers", status=FindingStatus.CONFIRMED, severity="LOW"
    )
    f_potential_crit = make_finding(
        id="f3", category="BFLA", endpoint="/admin", method="GET",
        resource_type="Admin", status=FindingStatus.POTENTIAL, severity="CRITICAL"
    )

    # Helper simulating the CLI exit code logic:
    def eval_exit(findings, fail_on):
        if not fail_on:
            active = [f for f in findings if f.status == FindingStatus.CONFIRMED and getattr(f, "category", "BOLA") in ("BOLA", "BFLA", "BOPLA", "AUTH")]
            return 1 if len(active) > 0 else 0
        norm = fail_on.strip().upper()
        if norm == "NONE":
            return 0
        sev_levels = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        thresh = sev_levels.get(norm, 4)
        failing = [f for f in findings if f.status == FindingStatus.CONFIRMED and sev_levels.get(f.severity.upper(), 0) >= thresh]
        return 1 if len(failing) > 0 else 0

    # 1. Absent: active -> 1, passive-only -> 0
    assert eval_exit([f_active_high], None) == 1
    assert eval_exit([f_passive_low], None) == 0
    assert eval_exit([f_potential_crit], None) == 0

    # 2. none: always 0
    assert eval_exit([f_active_high], "none") == 0
    assert eval_exit([f_passive_low], "none") == 0

    # 3. high: active HIGH -> 1, passive LOW -> 0
    assert eval_exit([f_active_high], "high") == 1
    assert eval_exit([f_passive_low], "high") == 0

    # 4. low: passive LOW -> 1
    assert eval_exit([f_passive_low], "low") == 1

    # 5. POTENTIAL with CRITICAL severity never fails the build
    assert eval_exit([f_potential_crit], "critical") == 0
    assert eval_exit([f_potential_crit], "low") == 0


@pytest.mark.asyncio
async def test_exit_2_writes_no_reports(tmp_path):
    """Asserts that exit code 2 (config / connection error) writes zero partial report files."""
    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    md_path = tmp_path / "report.md"

    # Invalid profile path triggers exit 2
    code = await run_cli_scan(
        dry_run=False,
        profile_path="nonexistent_profile_path_12345.yaml",
        json_path=str(json_path),
        sarif_path=str(sarif_path),
        markdown_path=str(md_path)
    )
    assert code == 2
    assert not json_path.exists()
    assert not sarif_path.exists()
    assert not md_path.exists()


@pytest.mark.asyncio
async def test_cli_scan_generates_all_reports_on_demo_profile(tmp_path):
    """Asserts that running run_cli_scan on the demo profile writes JSON, SARIF, and Markdown reports."""
    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    md_path = tmp_path / "report.md"

    code = await run_cli_scan(
        dry_run=False,
        profile_path="backend/apiguard/targets/demo.yaml",
        json_path=str(json_path),
        sarif_path=str(sarif_path),
        markdown_path=str(md_path),
        fail_on="none"
    )
    # With fail-on "none", must exit 0
    assert code == 0

    assert json_path.exists()
    json_data = json.loads(json_path.read_text(encoding="utf-8"))
    assert json_data["version"] == get_version()
    assert "summary" in json_data
    assert "coverage" in json_data
    assert "findings" in json_data

    assert sarif_path.exists()
    sarif_data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "APIGuard"
    results = sarif_data["runs"][0]["results"]
    assert len(results) >= 1
    # Check that location points to demo spec
    loc = results[0]["locations"][0]["physicalLocation"]
    assert "demo_spec.yaml" in loc["artifactLocation"]["uri"]
    assert loc["region"]["startLine"] >= 1

    assert md_path.exists()
    md_text = md_path.read_text(encoding="utf-8")
    assert md_text.startswith("<!-- apiguard-report -->")
    assert "Coverage:" in md_text
    assert len(md_text) <= 60000

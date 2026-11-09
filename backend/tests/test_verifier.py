import pytest
from apiguard.engine.verifier import DifferentialVerifier
from apiguard.engine.models import (
    ExecutionResult, Hypothesis, Rule, RuleType, FindingStatus, Provenance
)

def test_verifier_dynamic_value_extraction_different_seed():
    """
    Asserts confirmed findings derive from dynamically extracted owner-linked fields,
    not hardcoded strings, by using completely custom seed data.
    """
    hyp = Hypothesis(
        id="hyp_test",
        rule=Rule(rule_type=RuleType.OWNER_ONLY, resource_type="Document"),
        operation_id="getDocument",
        confidence=0.85,
        provenance=Provenance.OBSERVED
    )

    # Completely different seed data (Charlie with custom secret)
    owner_result = ExecutionResult(
        step_id="ctrl_1",
        operation_id="getDocument",
        identity_id="usr_charlie",
        method="GET",
        url="http://localhost:8000/docs/doc_99",
        status_code=200,
        duration_ms=12.0,
        sanitized_headers={},
        body={
            "doc_id": "doc_99",
            "owner_email": "charlie@aerospace-defense.org",
            "confidential_payload": "TOP-SECRET-MISSILE-GUIDANCE-V9",
            "billing_account": "ACC-99281-CHUCK"
        },
        correlation_id="c1"
    )

    probe_result = ExecutionResult(
        step_id="probe_1",
        operation_id="getDocument",
        identity_id="usr_adversary",
        method="GET",
        url="http://localhost:8000/docs/doc_99",
        status_code=200,
        duration_ms=11.0,
        sanitized_headers={},
        body={
            "doc_id": "doc_99",
            "owner_email": "charlie@aerospace-defense.org",
            "confidential_payload": "TOP-SECRET-MISSILE-GUIDANCE-V9",
            "billing_account": "ACC-99281-CHUCK"
        },
        correlation_id="c2"
    )

    finding = DifferentialVerifier.verify(
        operation_id="getDocument",
        endpoint="/docs/{doc_id}",
        method="GET",
        hypothesis=hyp,
        graph_path=["getDocument"],
        owner_result=owner_result,
        probe_result=probe_result
    )

    assert finding is not None
    assert finding.status == FindingStatus.CONFIRMED
    assert finding.severity == "CRITICAL"
    assert "owner_email" in finding.diff_fields
    assert "confidential_payload" in finding.diff_fields
    assert "billing_account" in finding.diff_fields

def test_verifier_trap_empty_body():
    """
    Trap 1: Server returns HTTP 200 with an empty body {}
    Must NEVER be flagged as CONFIRMED.
    """
    hyp = Hypothesis(
        id="hyp_test",
        rule=Rule(rule_type=RuleType.OWNER_ONLY, resource_type="Project"),
        operation_id="getProjectSummary",
        confidence=0.85,
        provenance=Provenance.OBSERVED
    )

    owner_res = ExecutionResult(
        step_id="c", operation_id="op", identity_id="a", method="GET", url="http://loc",
        status_code=200, duration_ms=5, sanitized_headers={}, body={"owner_email": "a@a.com"}, correlation_id="1"
    )
    # Empty body
    probe_res = ExecutionResult(
        step_id="p", operation_id="op", identity_id="b", method="GET", url="http://loc",
        status_code=200, duration_ms=5, sanitized_headers={}, body={}, correlation_id="2"
    )

    finding = DifferentialVerifier.verify(
        operation_id="getProjectSummary",
        endpoint="/projects/{id}/summary",
        method="GET",
        hypothesis=hyp,
        graph_path=["getProjectSummary"],
        owner_result=owner_res,
        probe_result=probe_res
    )

    assert finding is not None
    assert finding.status == FindingStatus.POTENTIAL  # NOT CONFIRMED!

def test_verifier_trap_legitimate_denial():
    """
    Trap 2: Server returns HTTP 404 for unauthorized identity
    Legitimate denial -> returns None (no finding).
    """
    hyp = Hypothesis(
        id="hyp_test",
        rule=Rule(rule_type=RuleType.OWNER_ONLY, resource_type="Project"),
        operation_id="getAudit",
        confidence=0.85,
        provenance=Provenance.OBSERVED
    )

    owner_res = ExecutionResult(
        step_id="c", operation_id="op", identity_id="a", method="GET", url="http://loc",
        status_code=200, duration_ms=5, sanitized_headers={}, body={"owner": "a"}, correlation_id="1"
    )
    probe_res = ExecutionResult(
        step_id="p", operation_id="op", identity_id="b", method="GET", url="http://loc",
        status_code=404, duration_ms=5, sanitized_headers={}, body={"detail": "Not found"}, correlation_id="2"
    )

    finding = DifferentialVerifier.verify(
        operation_id="getAudit",
        endpoint="/projects/{id}/audit",
        method="GET",
        hypothesis=hyp,
        graph_path=["getAudit"],
        owner_result=owner_res,
        probe_result=probe_res
    )

    assert finding is None  # Properly rejected, zero finding

def test_verifier_owner_control_failed_inconclusive():
    """
    If the owner's CONTROL request does not return success (e.g. /members 404 because
    the route doesn't exist on the target), the verification must return
    FindingStatus.INCONCLUSIVE, NEVER None (which signifies legitimate denial/secure).
    """
    hyp = Hypothesis(
        id="hyp_test_members_404",
        rule=Rule(rule_type=RuleType.OWNER_ONLY, resource_type="Project"),
        operation_id="getProjectMembers",
        confidence=0.85,
        provenance=Provenance.OBSERVED
    )

    # Owner got 404 (route does not exist on target)
    owner_res = ExecutionResult(
        step_id="c_members", operation_id="getProjectMembers", identity_id="a",
        method="GET", url="http://loc/projects/p1/members",
        status_code=404, duration_ms=5, sanitized_headers={},
        body={"detail": "Not Found"}, correlation_id="1"
    )
    # Probe also gets 404
    probe_res = ExecutionResult(
        step_id="p_members", operation_id="getProjectMembers", identity_id="b",
        method="GET", url="http://loc/projects/p1/members",
        status_code=404, duration_ms=5, sanitized_headers={},
        body={"detail": "Not Found"}, correlation_id="2"
    )

    finding = DifferentialVerifier.verify(
        operation_id="getProjectMembers",
        endpoint="/projects/{id}/members",
        method="GET",
        hypothesis=hyp,
        graph_path=["getProjectMembers"],
        owner_result=owner_res,
        probe_result=probe_res
    )

    # Must be INCONCLUSIVE, never None (which would mislabel as "TESTED: NO LEAK")
    assert finding is not None
    assert finding.status == FindingStatus.INCONCLUSIVE
    assert finding.control_evidence["status"] == 404
    assert finding.severity == "INFO"

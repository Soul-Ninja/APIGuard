import uuid
import json
from typing import Dict, Any, List, Optional, Tuple, Set
from apiguard.engine.models import (
    Finding, FindingStatus, ExecutionResult, Hypothesis
)

SENSITIVE_KEY_SUBSTRINGS = {
    "owner", "email", "user_id", "billing", "card", "confidential", 
    "secret", "token", "budget", "ssn", "passport", "private"
}

class DifferentialVerifier:
    """
    Evaluates response pairs between Owner (Control) and Adversary (Probe).
    Derived strictly from response body differential, NEVER status codes alone.
    """
    @staticmethod
    def _extract_sensitive_values(data: Any, path: str = "", extra_sensitive_fields: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Recursively extracts sensitive, owner-linked key-value pairs from the control payload.
        Combines default sensitive key substrings with any per-resource extra substrings.
        """
        results = {}
        all_substrings = SENSITIVE_KEY_SUBSTRINGS | {f.lower() for f in (extra_sensitive_fields or []) if f}
        if isinstance(data, dict):
            for k, v in data.items():
                current_path = f"{path}.{k}" if path else k
                k_lower = k.lower()
                if any(sub in k_lower for sub in all_substrings):
                    if v and not isinstance(v, (dict, list)):
                        results[current_path] = str(v)
                results.update(DifferentialVerifier._extract_sensitive_values(v, current_path, extra_sensitive_fields))
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                results.update(DifferentialVerifier._extract_sensitive_values(item, f"{path}[{idx}]", extra_sensitive_fields))
        return results

    @staticmethod
    def verify(
        operation_id: str,
        endpoint: str,
        method: str,
        hypothesis: Hypothesis,
        graph_path: List[str],
        owner_result: ExecutionResult,
        probe_result: ExecutionResult,
        owner_identity_id: str = "user_a",
        probe_identity_id: str = "user_b",
        sensitive_fields: Optional[List[str]] = None
    ) -> Optional[Finding]:
        # 1. Check for inconclusive execution (owner control did not succeed)
        if owner_result.status_code < 200 or owner_result.status_code >= 300 or probe_result.status_code == 0:
            return Finding(
                id=f"fnd_inconclusive_{uuid.uuid4().hex[:6]}",
                endpoint=endpoint,
                method=method,
                resource_type=hypothesis.rule.resource_type,
                status=FindingStatus.INCONCLUSIVE,
                confidence=0.10,
                severity="INFO",
                identities={"owner": owner_identity_id, "probe": probe_identity_id},
                hypothesis=hypothesis,
                graph_path=graph_path,
                control_evidence={"status": owner_result.status_code},
                probe_evidence={"status": probe_result.status_code, "error": probe_result.error},
                diff_fields=[],
                repro_curl=""
            )

        # 2. Check if probe was legitimately rejected (401, 403, 404 access controls when owner succeeded)
        if probe_result.status_code in {401, 403, 404}:
            return None

        # 3. VERIFIER TRAP: Empty or filtered 200 body
        probe_body = probe_result.body
        if not probe_body or probe_body == {} or probe_body == []:
            return Finding(
                id=f"fnd_potential_{uuid.uuid4().hex[:6]}",
                endpoint=endpoint,
                method=method,
                resource_type=hypothesis.rule.resource_type,
                status=FindingStatus.POTENTIAL,
                confidence=0.30,
                severity="LOW",
                identities={"owner": owner_identity_id, "probe": probe_identity_id},
                hypothesis=hypothesis,
                graph_path=graph_path,
                control_evidence={"status": 200},
                probe_evidence={"status": 200, "body": probe_body},
                diff_fields=[],
                repro_curl=""
            )

        # 4. DIFFERENTIAL ANALYSIS: Derives from owner-linked values in control body
        owner_sensitive_fields = DifferentialVerifier._extract_sensitive_values(owner_result.body, extra_sensitive_fields=sensitive_fields)
        probe_str_body = json.dumps(probe_body) if isinstance(probe_body, (dict, list)) else str(probe_body)

        leaked_fields = []
        for field_path, sensitive_val in owner_sensitive_fields.items():
            if sensitive_val in probe_str_body:
                leaked_fields.append(field_path)

        # If owner-linked data leaked into probe response -> CONFIRMED BOLA
        if leaked_fields:
            status = FindingStatus.CONFIRMED
            severity = "CRITICAL" if any("billing" in f or "card" in f or "secret" in f for f in leaked_fields) else "HIGH"
            confidence = min(0.98, hypothesis.confidence + 0.15)
        else:
            # If 200 returned but no sensitive field matched, downgrade to LIKELY or POTENTIAL
            status = FindingStatus.LIKELY
            severity = "MEDIUM"
            confidence = 0.50

        repro_curl = f"curl -X {method} '{probe_result.url}' -H 'Authorization: Bearer <USER_B_TOKEN>'"
        producer_label = graph_path[0] if graph_path else "Setup"

        return Finding(
            id=f"fnd_bola_{uuid.uuid4().hex[:6]}",
            endpoint=endpoint,
            method=method,
            resource_type=hypothesis.rule.resource_type,
            status=status,
            confidence=confidence,
            severity=severity,
            identities={"owner": owner_identity_id, "probe": probe_identity_id},
            hypothesis=hypothesis,
            graph_path=graph_path,
            control_evidence={"status": owner_result.status_code, "body": owner_result.body},
            probe_evidence={"status": probe_result.status_code, "body": probe_result.body},
            diff_fields=leaked_fields,
            repro_curl=repro_curl,
            reproduction_steps=[
                f"1. Authenticate as {owner_identity_id} to establish resource state.",
                f"2. Note generated resource ID from control body.",
                f"3. Replay {method} {endpoint} substituting {probe_identity_id}'s bearer token.",
                f"4. Observe HTTP 200 OK leaking owner fields: {', '.join(leaked_fields)}."
            ],
            minimized_sequence=[f"{producer_label} (Setup)", f"{method} {endpoint} (Probe)"]
        )

import json
import re
import time
import uuid
from typing import List, Dict, Any, Optional, Callable, Union, Tuple
from urllib.parse import urlparse
import httpx
from apiguard.engine.models import (
    Operation, IdentityProfile, Finding, FindingStatus, PlanStep, ScanEvent,
    NodeType, EdgeType, Provenance, Rule, RuleType, Hypothesis, ResourceSkip, ScanCoverage
)
from apiguard.engine.graph import ResourceGraph
from apiguard.engine.inference import InferenceEngine
from apiguard.engine.executor import SafeExecutor, SecurityViolationError
from apiguard.engine.verifier import DifferentialVerifier
from apiguard.engine.target import (
    TargetProfile, load_target_profile, get_path, build_body_from_schema,
    is_admin_operation, is_documented_writable, get_schema_properties
)

DEFAULT_BASE = "http://127.0.0.1:8000/target"
OK = lambda res: 200 <= res.status_code < 300


def _is_error_payload(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    lower_keys = {str(k).lower() for k in data.keys()}
    if "error" in lower_keys or "errors" in lower_keys:
        return True
    if "detail" in lower_keys:
        val = str(data.get("detail", "")).lower()
        if any(w in val for w in ["forbidden", "unauthorized", "denied", "not allowed", "invalid", "error"]):
            return True
    if "message" in lower_keys:
        val = str(data.get("message", "")).lower()
        if any(w in val for w in ["forbidden", "unauthorized", "denied", "not allowed", "invalid", "error"]):
            return True
    return False


def _shape_matches(ctrl: Any, probe: Any) -> bool:
    if ctrl is None or probe is None:
        return False
    if probe == {} or probe == [] or probe == "":
        return False
    if _is_error_payload(probe):
        return False

    # Check dict
    if isinstance(ctrl, dict) and isinstance(probe, dict):
        c_keys = set(ctrl.keys())
        p_keys = set(probe.keys())
        if not c_keys or not p_keys:
            return False
        shared = c_keys & p_keys
        return (len(shared) / len(c_keys) >= 0.5) and len(shared) >= 1

    # Check list
    if isinstance(ctrl, list) and isinstance(probe, list):
        if len(ctrl) == 0 or len(probe) == 0:
            return False
        c_item = ctrl[0]
        p_item = probe[0]
        if type(c_item) != type(p_item):
            return False
        if isinstance(c_item, dict) and isinstance(p_item, dict):
            c_keys = set(c_item.keys())
            p_keys = set(p_item.keys())
            if not c_keys or not p_keys:
                return False
            shared = c_keys & p_keys
            return (len(shared) / len(c_keys) >= 0.5) and len(shared) >= 1
        return True

    return False


class GraphGuidedScanner:
    """Graph-driven BOLA scanner: setup, control and probe steps are all derived from the resource DAG."""

    def __init__(self, executor: SafeExecutor, base_url: str = DEFAULT_BASE,
                 disable_propagation: bool = False, target_profile: Optional[Any] = None):
        self.executor = executor
        self.disable_propagation = disable_propagation
        self.coverage: ScanCoverage = ScanCoverage()
        explicit = target_profile is not None
        try:
            self.target_profile = load_target_profile(target_profile) if isinstance(target_profile, str) \
                else target_profile or load_target_profile("targets/demo.yaml")
        except Exception:
            if explicit:
                raise  # a profile the caller named must never silently fall back to the demo
            self.target_profile = None
        # an explicit base_url wins; otherwise an explicit profile's own URL
        profile_url = self.target_profile.base_url if explicit else ""
        self.base_url = (profile_url if base_url == DEFAULT_BASE and profile_url else base_url).rstrip("/")
        self.graph = ResourceGraph()
        self.inference = InferenceEngine(self.graph, target_profile=self.target_profile)

    # ---- helpers -------------------------------------------------------------

    async def _emit(self, cb: Optional[Callable], event_type: str, message: str, phase: Optional[str] = None, data: Optional[Dict[str, Any]] = None):
        if not cb:
            return
        event = ScanEvent(event_id=f"ev_{uuid.uuid4().hex[:6]}", scan_id="active_scan", timestamp=time.time(),
                          event_type=event_type, phase=phase, message=message, data=data or {})
        try:
            res = cb(event)
            if hasattr(res, "__await__"):
                await res
        except Exception:
            pass  # a broken UI callback must never abort a scan

    def _step(self, sid: str, who: IdentityProfile, op: Operation, purpose: str, obj_id=None, body=None, url: Optional[str] = None) -> PlanStep:
        if url is None:
            url = f"{self.base_url}{op.path}"
            if obj_id is not None and op.path_params:
                url = url.replace(f"{{{op.path_params[0]}}}", str(obj_id))
        return PlanStep(step_id=sid, identity_id=who.identity_id, operation_id=op.operation_id, method=op.method,
                        path_template=op.path, url=url, headers=who.get_auth_headers(), json_body=body, purpose=purpose)

    async def _execute_and_emit(self, step: PlanStep, on_event, client=None):
        tag, phase = f"[{step.purpose.upper()}]", "B" if step.purpose == "probe_adversary" else "A"
        base = {"step_id": step.step_id, "operation_id": step.operation_id}
        await self._emit(on_event, "request_sent", f"{tag} Sending {step.method} {step.url} as {step.identity_id}", phase,
                         {**base, "identity": step.identity_id, "method": step.method, "url": step.url,
                          "headers": self.executor.sanitize_headers(step.headers)})
        res = await self.executor.execute_step(step, client=client)
        await self._emit(on_event, "response_received", f"{tag} Received HTTP {res.status_code} for {step.method} {step.url} ({res.duration_ms}ms)", phase,
                         {**base, "status_code": res.status_code, "duration_ms": res.duration_ms, "headers": res.sanitized_headers})
        return res

    async def _inconclusive(self, on_event, op: Operation, res, phase: str):
        await self._emit(on_event, "test_inconclusive", f"control failed ({res.status_code}), test inconclusive", phase,
                         {"operation_id": op.operation_id, "status": "inconclusive", "status_code": res.status_code, "endpoint": op.path})

    async def _denied(self, on_event, op: Operation, res, phase: str, message: str, status: str = "secure"):
        await self._emit(on_event, "probe_denied", message, phase,
                         {"operation_id": op.operation_id, "status": status, "status_code": res.status_code, "endpoint": op.path})

    async def _confirm(self, on_event, finding: Finding, label: str, setup=None, probe=None, client=None, id_path="id"):
        if setup:
            await self._minimize_and_store(finding, setup, probe, client, id_path)
        await self._emit(on_event, "finding_confirmed", f"[ALERT] Confirmed {label}", "C", finding.model_dump())

    @staticmethod
    def _adhoc_hyp(op: Operation, resource_type: str = "Resource", owner_field: str = "owner_id") -> Hypothesis:
        return Hypothesis(id=f"hyp_adhoc_{op.operation_id}", rule=Rule(rule_type=RuleType.OWNER_ONLY, resource_type=resource_type, owner_field=owner_field),
                          operation_id=op.operation_id, confidence=0.50, provenance=Provenance.PROPAGATED)

    def _bfs_path(self, start: str, end: str) -> List[str]:
        """Shortest op-to-op path through the DAG edges, annotated with edge types."""
        queue, visited = [[start]], {start}
        while queue:
            path = queue.pop(0)
            if path[-1] == end:
                return path
            for e in self.graph.edges:
                if e.from_node == path[-1] and e.to_node not in visited:
                    visited.add(e.to_node)
                    queue.append(path + [f"({e.type.value})", e.to_node])
        return [start, "(PROPAGATED)", end]

    # ---- scan ----------------------------------------------------------------

    async def run_scan(self, operations: List[Operation], user_a: IdentityProfile, user_b: IdentityProfile,
                       enable_mutations: bool = False, on_event: Optional[Callable] = None,
                       client: Optional[httpx.AsyncClient] = None,
                       admin_user: Optional[IdentityProfile] = None,
                       enable_bopla: bool = True) -> List[Finding]:
        self.graph.build_from_operations(operations)
        self.coverage = ScanCoverage()

        login_paths = set()
        if self.target_profile and getattr(self.target_profile, "login", None) and getattr(self.target_profile.login, "path", None):
            login_paths.add(self.target_profile.login.path)
        else:
            login_paths.add("/auth/login")

        def _is_login_resource(res_node) -> bool:
            rname = res_node.metadata.get("resource_name", "") or res_node.label or res_node.id
            rpath = "/" + rname.strip("/")
            res_ops = [
                self.graph.operations[e.from_node]
                for e in self.graph.edges
                if e.to_node == res_node.id and e.type == EdgeType.OPERATES_ON and e.from_node in self.graph.operations
            ]
            if not res_ops:
                res_ops = [op for op in operations if any(s == rname for s in op.path.split("/") if s)]

            for lp in login_paths:
                norm_lp = "/" + lp.strip("/")
                if rpath.lower() == norm_lp.lower() or rname.lower() == lp.strip("/").lower():
                    return True
                if res_ops and all(
                    ("/" + op.path.strip("/")).lower() == norm_lp.lower() or
                    ("/" + op.path.strip("/")).lower().startswith(norm_lp.lower() + "/")
                    for op in res_ops
                ):
                    return True
                if norm_lp.lower().startswith(rpath.lower() + "/") and rname.lower() in {"auth", "login", "oauth", "token"}:
                    if res_ops and all(
                        ("/" + op.path.strip("/")).lower().startswith(rpath.lower() + "/")
                        for op in res_ops
                    ):
                        return True
            return False

        def _is_excluded_from_bola(res_node) -> bool:
            if _is_login_resource(res_node):
                return True
            rname = res_node.metadata.get("resource_name", "") or res_node.label or res_node.id
            res_ops = [
                self.graph.operations[e.from_node]
                for e in self.graph.edges
                if e.to_node == res_node.id and e.type == EdgeType.OPERATES_ON and e.from_node in self.graph.operations
            ]
            if not res_ops:
                res_ops = [op for op in operations if any(s == rname for s in op.path.split("/") if s)]
            if res_ops and all(is_admin_operation(op, self.target_profile) for op in res_ops):
                return True
            return False

        all_res_nodes = [n for n in self.graph.nodes.values() if n.type == NodeType.RESOURCE_TYPE]
        resource_nodes = [n for n in all_res_nodes if not _is_excluded_from_bola(n)]
        for res_node in resource_nodes:
            rname = res_node.metadata.get("resource_name", "") or res_node.label or res_node.id
            if rname and rname not in self.coverage.resources_found:
                self.coverage.resources_found.append(rname)

        findings: List[Finding] = []
        harvested_ids: Dict[str, str] = {}
        harvested_for_bopla: List[Tuple[Any, str, Operation, Operation, str, str, Any, str]] = []
        recorded_responses: List[Tuple[PlanStep, Any]] = []

        async def ex(step: PlanStep):
            res = await self._execute_and_emit(step, on_event, client)
            recorded_responses.append((step, res))
            return res

        for res_node in resource_nodes:
            name = res_node.metadata.get("resource_name", "")
            if not name:
                continue
            id_node = next((n for n in self.graph.nodes.values() if n.type == NodeType.IDENTIFIER and name in n.id), None)
            producer_edge = id_node and next((e for e in self.graph.edges if e.to_node == id_node.id and e.type == EdgeType.PRODUCES), None)
            producer = producer_edge and self.graph.operations.get(producer_edge.from_node)
            if not producer:
                reason = "no producer operation found in spec"
                self.coverage.skipped.append(ResourceSkip(resource=name, reason=reason))
                await self._emit(on_event, "log", f"[SKIPPED] Resource '{name}' skipped: {reason}", "A")
                continue

            override = self.target_profile.get_resource_override(name) if self.target_profile else None
            id_path = override.id_path if override and override.id_path else "id"
            sensitive_fields = override.sensitive_fields if override and override.sensitive_fields else []
            owner_field = override.owner_field if override and override.owner_field else "owner_id"

            if override and override.body is not None:
                body = override.body
            else:
                body = build_body_from_schema(producer.request_schema) if producer.request_schema else {}

            # Phase A: harvest a resource as user A
            setup = self._step(f"harvest_{producer.operation_id}", user_a, producer, "setup", body=body)
            setup_res = await ex(setup)

            if setup_res.status_code in {401, 403}:
                reason = f"owner identity '{user_a.identity_id}' credentials were rejected (HTTP {setup_res.status_code})"
                self.coverage.skipped.append(ResourceSkip(resource=name, reason=reason))
                await self._emit(on_event, "log", f"[SKIPPED] Resource '{name}' skipped: {reason}", "A")
                continue

            if setup_res.status_code == 0:
                err_detail = setup_res.error or "unreachable host"
                reason = f"connection error ({err_detail})"
                self.coverage.skipped.append(ResourceSkip(resource=name, reason=reason))
                await self._emit(on_event, "log", f"[SKIPPED] Resource '{name}' skipped: {reason}", "A")
                continue

            if setup_res.status_code >= 400:
                reason = f"HTTP status {setup_res.status_code} on create"
                self.coverage.skipped.append(ResourceSkip(resource=name, reason=reason))
                await self._emit(on_event, "log", f"[SKIPPED] Resource '{name}' skipped: {reason}", "A")
                continue

            obj_id = get_path(setup_res.body, id_path)
            if obj_id is None:
                reason = f"missing id at id_path '{id_path}' in response from {producer.operation_id}"
                self.coverage.skipped.append(ResourceSkip(resource=name, reason=reason))
                await self._emit(on_event, "log", f"[SKIPPED] Resource '{name}' skipped: {reason}", "A")
                continue

            harvested_ids[name.lower()] = str(obj_id)
            harvested_ids[name.lower().rstrip("s")] = str(obj_id)
            harvested_ids[f"{name.lower().rstrip('s')}_id"] = str(obj_id)
            harvested_ids[f"{name.lower()}_id"] = str(obj_id)
            if id_node and id_node.metadata.get("param_name"):
                harvested_ids[id_node.metadata["param_name"].lower()] = str(obj_id)

            rtype = res_node.label or name.capitalize()

            primary = next((o for o in operations if o.method == "GET" and o.path_params and name in o.path and len(o.path.split("/")) <= 3), None)
            if not primary:
                reason = "no primary read operation found"
                self.coverage.skipped.append(ResourceSkip(resource=name, reason=reason))
                await self._emit(on_event, "log", f"[SKIPPED] Resource '{name}' skipped: {reason}", "A")
                continue

            ctrl = await ex(self._step(f"ctrl_{primary.operation_id}", user_a, primary, "control_owner", obj_id))
            if not OK(ctrl):
                if ctrl.status_code == 0:
                    reason = f"connection error ({ctrl.error or 'unreachable host'}) on control read"
                else:
                    reason = f"control read failed (HTTP {ctrl.status_code})"
                self.coverage.skipped.append(ResourceSkip(resource=name, reason=reason))
                await self._inconclusive(on_event, primary, ctrl, "A")
                continue

            probe_step = self._step(f"probe_{primary.operation_id}", user_b, primary, "probe_adversary", obj_id)
            probe = await ex(probe_step)
            if name not in self.coverage.resources_tested:
                self.coverage.resources_tested.append(name)
            harvested_for_bopla.append((res_node, name, producer, primary, id_path, owner_field, body, str(obj_id)))

            hyp = self.inference.record_control_observation(primary.operation_id, ctrl, probe)
            if hyp:
                await self._denied(on_event, primary, probe, "A", f"[VERIFIER] Access denied for unauthorized probe on {primary.path} (HTTP {probe.status_code})")
                await self._emit(on_event, "hypothesis_validated", f"[INFERENCE] Validated rule 'owner_only' on {primary.method} {primary.path}", "A",
                                 {"hypothesis_id": hyp.id, "confidence": hyp.confidence})
                if not self.disable_propagation:
                    for p in self.inference.propagate_rules(primary.operation_id):
                        await self._emit(on_event, "hypothesis_propagated", f"[PROPAGATION] Propagated candidate ownership rule to {p.operation_id}", "B",
                                         {"candidate_id": p.id, "confidence": p.confidence})
            elif probe.status_code == 200:  # the primary read itself leaks
                hyp = self.inference.hypotheses.get(primary.operation_id) or self._adhoc_hyp(primary, rtype, owner_field)
                f = DifferentialVerifier.verify(operation_id=primary.operation_id, endpoint=primary.path, method=primary.method,
                                                hypothesis=hyp, graph_path=[producer.operation_id, primary.operation_id],
                                                owner_result=ctrl, probe_result=probe,
                                                owner_identity_id=user_a.identity_id, probe_identity_id=user_b.identity_id,
                                                sensitive_fields=sensitive_fields)
                if f and f.status == FindingStatus.CONFIRMED:
                    await self._confirm(on_event, f, f"direct BOLA at {primary.path}", setup, probe_step, client, id_path)
                    findings.append(f)

            # graph-adjacent and consumer ops; DELETE is handled last on a disposable resource
            others = [o for o in operations if o.path_params and o.operation_id != primary.operation_id]
            test_ops = [] if self.disable_propagation else (
                [o for o in others if o.method == "GET"] +
                ([o for o in others if o.method in {"PATCH", "PUT"}] if enable_mutations else []))

            for op in test_ops:
                mutates = op.method in {"PATCH", "PUT"}
                c = await ex(self._step(f"ctrl_{op.operation_id}", user_a, op, "control_owner", obj_id,
                                        {"name": "Mutated Name", "budget": "$999,000"} if mutates else None))
                if not OK(c):
                    await self._inconclusive(on_event, op, c, "B")
                    continue
                p_step = self._step(f"probe_{op.operation_id}", user_b, op, "probe_adversary", obj_id,
                                    {"name": "Attacker Hijack", "budget": "$1"} if mutates else None)
                p = await ex(p_step)
                f = DifferentialVerifier.verify(operation_id=op.operation_id, endpoint=op.path, method=op.method,
                                                hypothesis=self.inference.hypotheses.get(op.operation_id) or self._adhoc_hyp(op, rtype, owner_field),
                                                graph_path=self._bfs_path(primary.operation_id, op.operation_id),
                                                owner_result=c, probe_result=p,
                                                owner_identity_id=user_a.identity_id, probe_identity_id=user_b.identity_id,
                                                sensitive_fields=sensitive_fields)
                if f and f.status == FindingStatus.CONFIRMED:
                    await self._confirm(on_event, f, f"BOLA at {op.method} {op.path}", setup, p_step, client, id_path)
                    findings.append(f)
                elif f:  # POTENTIAL/REJECTED: owner OK but probe got an empty body, no leak
                    await self._denied(on_event, op, p, "C", f"[VERIFIER] Trap evaluated on {op.path}: empty response (no leak)", "secure_empty_body")
                else:
                    await self._denied(on_event, op, p, "C", f"[VERIFIER] Access denied for unauthorized probe on {op.path} (HTTP {p.status_code})")

            if enable_mutations:
                for op in [o for o in others if o.method == "DELETE"]:
                    disp_id = get_path((await ex(self._step(f"disp_del_setup_{uuid.uuid4().hex[:4]}", user_a, producer, "setup", body=body))).body, id_path) or "proj_disp"
                    del_probe = self._step(f"probe_del_{disp_id}", user_b, op, "probe_adversary", disp_id)
                    res = await ex(del_probe)
                    if res.status_code == 200:
                        f = Finding(id=f"fnd_del_{uuid.uuid4().hex[:6]}", endpoint=op.path, method="DELETE", resource_type=rtype,
                                    status=FindingStatus.CONFIRMED, confidence=0.80, severity="CRITICAL",
                                    identities={"owner": user_a.identity_id, "probe": user_b.identity_id},
                                    hypothesis=self._adhoc_hyp(op, rtype, owner_field), graph_path=[producer.operation_id, "PRODUCES", op.operation_id],
                                    control_evidence={"status": 403}, probe_evidence={"status": 200},
                                    diff_fields=["unauthorized_deletion"],
                                    repro_curl=f"curl -X DELETE '{del_probe.url}' -H 'Authorization: Bearer <TOKEN>'")
                        findings.append(f)
                        await self._confirm(on_event, f, f"BOLA on DELETE at {op.path}")
                        continue
                    # non-owner denied: the owner deleting it doubles as cleanup
                    cleanup = await ex(self._step(f"ctrl_del_{disp_id}", user_a, op, "control_owner", disp_id))
                    if cleanup.status_code == 200:
                        await self._denied(on_event, op, res, "C", f"[VERIFIER] Access denied for unauthorized DELETE on {op.path} (HTTP {res.status_code}); cleanup succeeded")
                    else:
                        await self._inconclusive(on_event, op, cleanup, "C")

        # ---- Phase: BFLA (OWASP API5 - Broken Function Level Authorization) ----
        admin_ops = [op for op in operations if is_admin_operation(op, self.target_profile)]
        for op in admin_ops:
            op_key = f"{op.method} {op.path}"
            if op_key not in self.coverage.admin_operations_found:
                self.coverage.admin_operations_found.append(op_key)

        if not admin_user:
            if admin_ops:
                await self._emit(on_event, "log", "[BFLA] Admin identity not configured; skipping BFLA scan.", "A")
        else:
            for op in admin_ops:
                op_key = f"{op.method} {op.path}"
                is_mutation = op.method in {"POST", "PUT", "PATCH", "DELETE"}
                if is_mutation and not enable_mutations:
                    await self._emit(on_event, "log", f"[BFLA] Mutating admin op {op.method} {op.path} skipped (--mutations not set)", "A")
                    continue

                body = None
                if op.request_schema:
                    body = build_body_from_schema(op.request_schema)

                # Path parameter resolution: fill from harvested ids or skip
                resolved_url = f"{self.base_url}{op.path}"
                missing_param = None
                p_names = op.path_params or [p for p in re.findall(r"\{([a-zA-Z0-9_]+)\}", op.path)]
                if p_names:
                    for param in p_names:
                        p_lower = param.lower()
                        matched_id = None
                        if p_lower in harvested_ids:
                            matched_id = harvested_ids[p_lower]
                        elif p_lower.endswith("_id") and p_lower[:-3] in harvested_ids:
                            matched_id = harvested_ids[p_lower[:-3]]
                        elif p_lower in {"id", "pk"}:
                            segments = [s.lower().strip("{}") for s in op.path.split("/") if s and s != f"{{{param}}}"]
                            for seg in segments:
                                if seg in {"admin", "api", "v1", "v2", "v3"}:
                                    continue
                                if seg in harvested_ids:
                                    matched_id = harvested_ids[seg]
                                    break
                                if seg.rstrip("s") in harvested_ids:
                                    matched_id = harvested_ids[seg.rstrip("s")]
                                    break
                                if f"{seg}_id" in harvested_ids:
                                    matched_id = harvested_ids[f"{seg}_id"]
                                    break
                                if f"{seg.rstrip('s')}_id" in harvested_ids:
                                    matched_id = harvested_ids[f"{seg.rstrip('s')}_id"]
                                    break
                        if matched_id is not None:
                            resolved_url = resolved_url.replace(f"{{{param}}}", str(matched_id))
                        else:
                            missing_param = param
                            break

                if missing_param is not None:
                    reason = f"needs path parameter {missing_param}"
                    self.coverage.skipped.append(ResourceSkip(resource=f"{op.method} {op.path}", reason=reason))
                    await self._emit(on_event, "log", f"[SKIPPED] Admin op '{op.method} {op.path}' skipped: {reason}", "A")
                    continue

                # Control step: call as admin
                ctrl_step = self._step(f"bfla_ctrl_{op.operation_id}", admin_user, op, "control_admin", body=body, url=resolved_url)
                ctrl_res = await ex(ctrl_step)

                if not (200 <= ctrl_res.status_code < 300):
                    reason = f"admin control call returned HTTP {ctrl_res.status_code}" if ctrl_res.status_code > 0 else f"admin control call connection error: {ctrl_res.error or 'unreachable'}"
                    self.coverage.skipped.append(ResourceSkip(resource=f"{op.method} {op.path}", reason=reason))
                    await self._inconclusive(on_event, op, ctrl_res, "A")
                    continue

                # Probe step: call as attacker (user_b)
                probe_step = self._step(f"bfla_probe_{op.operation_id}", user_b, op, "probe_adversary", body=body, url=resolved_url)
                probe_res = await ex(probe_step)

                if op_key not in self.coverage.admin_operations_tested:
                    self.coverage.admin_operations_tested.append(op_key)

                if 200 <= probe_res.status_code < 300:
                    is_match = _shape_matches(ctrl_res.body, probe_res.body)
                    auth_h = "-H 'Authorization: Bearer <USER_B_TOKEN>'" if user_b.token else ""
                    repro = f"curl -X {op.method} '{probe_step.url}' {auth_h}".strip()
                    status = FindingStatus.CONFIRMED if is_match else FindingStatus.POTENTIAL
                    confidence = 0.95 if is_match else 0.40
                    severity = "HIGH" if is_match else "LOW"
                    f = Finding(
                        id=f"fnd_bfla_{uuid.uuid4().hex[:6]}",
                        category="BFLA",
                        severity=severity,
                        endpoint=op.path,
                        method=op.method,
                        resource_type="Admin",
                        status=status,
                        confidence=confidence,
                        identities={"admin": admin_user.identity_id, "probe": user_b.identity_id},
                        hypothesis=Hypothesis(
                            id=f"hyp_bfla_{op.operation_id}",
                            rule=Rule(rule_type=RuleType.OWNER_ONLY, resource_type="Admin", owner_field="role"),
                            operation_id=op.operation_id,
                            confidence=confidence,
                            provenance=Provenance.DOCUMENTED
                        ),
                        graph_path=[f"{op.method} {op.path} (BFLA: Admin Function Exposed)"],
                        control_evidence={"status_code": ctrl_res.status_code, "body": ctrl_res.body},
                        probe_evidence={"status_code": probe_res.status_code, "body": probe_res.body},
                        diff_fields=[],
                        repro_curl=repro,
                        reproduction_steps=[
                            f"1. Authenticate as admin user ({admin_user.identity_id}) and call {op.method} {op.path} -> HTTP {ctrl_res.status_code}",
                            f"2. Authenticate as non-admin attacker ({user_b.identity_id}) with bearer token <USER_B_TOKEN> and call {op.method} {op.path} -> HTTP {probe_res.status_code}"
                        ]
                    )
                    findings.append(f)
                    if is_match:
                        await self._confirm(on_event, f, f"BFLA on {op.method} {op.path}")
                    else:
                        await self._emit(on_event, "log", f"[POTENTIAL] BFLA on {op.method} {op.path}: probe returned 2xx but body shape differed or indicated error", "C", f.model_dump())
                elif probe_res.status_code in {401, 403, 404}:
                    await self._denied(on_event, op, probe_res, "B", f"[BFLA] Probe denied with HTTP {probe_res.status_code} (Secure)")

        # ---- Phase: BOPLA (OWASP API3 - Broken Object Property Level Authorization) ----
        if enable_bopla:
            # Part A - Mass assignment (active)
            for (res_node, name, producer, primary, id_path, owner_field, body, obj_id) in harvested_for_bopla:
                check_name = f"Mass Assignment: {producer.method} {producer.path}"
                if check_name not in self.coverage.bopla_operations_found:
                    self.coverage.bopla_operations_found.append(check_name)

                injected_fields: Dict[str, Any] = {
                    "role": "admin",
                    "is_admin": True,
                    owner_field: user_b.identity_id
                }
                if self.target_profile and getattr(self.target_profile, "mass_assignment_fields", None):
                    extra_ma = self.target_profile.mass_assignment_fields
                    if isinstance(extra_ma, dict):
                        injected_fields.update(extra_ma)
                    elif isinstance(extra_ma, list):
                        for item in extra_ma:
                            if isinstance(item, dict):
                                injected_fields.update(item)
                            elif isinstance(item, str):
                                injected_fields[item] = "admin"

                inj_body = dict(body) if isinstance(body, dict) else {}
                inj_body.update(injected_fields)

                inj_step = self._step(f"bopla_inject_{producer.operation_id}", user_a, producer, "probe_mass_assignment", body=inj_body)
                inj_res = await ex(inj_step)

                if not (200 <= inj_res.status_code < 300):
                    reason = f"HTTP status {inj_res.status_code} on create injection" if inj_res.status_code > 0 else "connection error on create injection"
                    self.coverage.skipped.append(ResourceSkip(resource=check_name, reason=reason))
                    continue

                inj_id = get_path(inj_res.body, id_path) or obj_id
                read_step = self._step(f"bopla_read_{primary.operation_id}", user_a, primary, "control_owner", inj_id)
                read_res = await ex(read_step)

                if not (200 <= read_res.status_code < 300):
                    reason = f"read-back failed (HTTP {read_res.status_code})" if read_res.status_code > 0 else "connection error on read-back"
                    self.coverage.skipped.append(ResourceSkip(resource=check_name, reason=reason))
                    continue

                if check_name not in self.coverage.bopla_operations_tested:
                    self.coverage.bopla_operations_tested.append(check_name)

                persisted_undocumented = []
                echoed_undocumented = []
                for k, expected_v in injected_fields.items():
                    if is_documented_writable(producer.request_schema, k):
                        continue
                    actual_v = get_path(read_res.body, k) if isinstance(read_res.body, dict) else None
                    if actual_v is not None and str(actual_v) == str(expected_v):
                        persisted_undocumented.append(k)
                    else:
                        echo_v = get_path(inj_res.body, k) if isinstance(inj_res.body, dict) else None
                        if echo_v is not None and str(echo_v) == str(expected_v):
                            echoed_undocumented.append(k)

                if persisted_undocumented:
                    f = Finding(
                        id=f"fnd_bopla_ma_{uuid.uuid4().hex[:6]}",
                        category="BOPLA",
                        severity="HIGH",
                        endpoint=producer.path,
                        method=producer.method,
                        resource_type=res_node.label or name.capitalize(),
                        status=FindingStatus.CONFIRMED,
                        confidence=0.95,
                        identities={"owner": user_a.identity_id, "probe": user_b.identity_id},
                        hypothesis=Hypothesis(
                            id=f"hyp_bopla_{producer.operation_id}",
                            rule=Rule(rule_type=RuleType.OWNER_ONLY, resource_type=res_node.label or name.capitalize(), owner_field=owner_field),
                            operation_id=producer.operation_id,
                            confidence=0.95,
                            provenance=Provenance.DOCUMENTED
                        ),
                        graph_path=[f"{producer.method} {producer.path} (Mass Assignment: Injected Undocumented Fields Persisted)"],
                        control_evidence={"status": inj_res.status_code, "injected_fields": list(injected_fields.keys())},
                        probe_evidence={"status": read_res.status_code, "persisted_fields": persisted_undocumented},
                        diff_fields=persisted_undocumented,
                        repro_curl=f"curl -X {producer.method} '{inj_step.url}' -H 'Authorization: Bearer <USER_A_TOKEN>' -H 'Content-Type: application/json' -d '{json.dumps(inj_body)}'",
                        reproduction_steps=[
                            f"1. As owner ({user_a.identity_id}) with bearer token <USER_A_TOKEN>, send {producer.method} {producer.path} with fields: {', '.join(persisted_undocumented)}",
                            f"2. Read back {primary.method} {read_step.url} and observe persisted undocumented properties: {', '.join(persisted_undocumented)}"
                        ]
                    )
                    findings.append(f)
                    await self._confirm(on_event, f, f"BOPLA Mass Assignment on {producer.method} {producer.path}")
                elif echoed_undocumented:
                    f = Finding(
                        id=f"fnd_bopla_ma_{uuid.uuid4().hex[:6]}",
                        category="BOPLA",
                        severity="LOW",
                        endpoint=producer.path,
                        method=producer.method,
                        resource_type=res_node.label or name.capitalize(),
                        status=FindingStatus.POTENTIAL,
                        confidence=0.40,
                        identities={"owner": user_a.identity_id, "probe": user_b.identity_id},
                        hypothesis=Hypothesis(
                            id=f"hyp_bopla_{producer.operation_id}",
                            rule=Rule(rule_type=RuleType.OWNER_ONLY, resource_type=res_node.label or name.capitalize(), owner_field=owner_field),
                            operation_id=producer.operation_id,
                            confidence=0.40,
                            provenance=Provenance.DOCUMENTED
                        ),
                        graph_path=[f"{producer.method} {producer.path} (Mass Assignment: Echoed in create response but not persisted)"],
                        control_evidence={"status": inj_res.status_code, "echoed_fields": echoed_undocumented},
                        probe_evidence={"status": read_res.status_code},
                        diff_fields=echoed_undocumented,
                        repro_curl=f"curl -X {producer.method} '{inj_step.url}' -H 'Authorization: Bearer <USER_A_TOKEN>' -H 'Content-Type: application/json' -d '{json.dumps(inj_body)}'",
                        reproduction_steps=[
                            f"1. As owner ({user_a.identity_id}) with bearer token <USER_A_TOKEN>, send {producer.method} {producer.path} with fields: {', '.join(echoed_undocumented)}",
                            f"2. Fields were echoed in create response but not found on read-back."
                        ]
                    )
                    findings.append(f)
                    await self._emit(on_event, "log", f"[POTENTIAL] BOPLA on {producer.method} {producer.path}: fields echoed but not persisted", "C", f.model_dump())

                # Check mutation operations (PATCH / PUT)
                others = [o for o in operations if o.path_params and name in o.path]
                mut_ops = [o for o in others if o.method in {"PATCH", "PUT"}]
                for mop in mut_ops:
                    m_key = f"Mass Assignment: {mop.method} {mop.path}"
                    if m_key not in self.coverage.bopla_operations_found:
                        self.coverage.bopla_operations_found.append(m_key)
                    if not enable_mutations:
                        reason = "--mutations not set"
                        self.coverage.skipped.append(ResourceSkip(resource=m_key, reason=reason))
                        continue
                    m_step = self._step(f"bopla_mut_{mop.operation_id}", user_a, mop, "probe_mass_assignment", obj_id, body=injected_fields)
                    m_res = await ex(m_step)
                    if not (200 <= m_res.status_code < 300):
                        reason = f"HTTP status {m_res.status_code} on mutation injection"
                        self.coverage.skipped.append(ResourceSkip(resource=m_key, reason=reason))
                        continue
                    m_read = await ex(self._step(f"bopla_mread_{primary.operation_id}", user_a, primary, "control_owner", obj_id))
                    if not (200 <= m_read.status_code < 300):
                        reason = f"read-back failed (HTTP {m_read.status_code}) after mutation"
                        self.coverage.skipped.append(ResourceSkip(resource=m_key, reason=reason))
                        continue
                    if m_key not in self.coverage.bopla_operations_tested:
                        self.coverage.bopla_operations_tested.append(m_key)
                    m_persisted = [k for k, ev in injected_fields.items() if not is_documented_writable(mop.request_schema, k) and isinstance(m_read.body, dict) and str(m_read.body.get(k)) == str(ev)]
                    m_echoed = [k for k, ev in injected_fields.items() if not is_documented_writable(mop.request_schema, k) and k not in m_persisted and isinstance(m_res.body, dict) and str(m_res.body.get(k)) == str(ev)]
                    if m_persisted:
                        f = Finding(
                            id=f"fnd_bopla_mut_{uuid.uuid4().hex[:6]}",
                            category="BOPLA",
                            severity="HIGH",
                            endpoint=mop.path,
                            method=mop.method,
                            resource_type=res_node.label or name.capitalize(),
                            status=FindingStatus.CONFIRMED,
                            confidence=0.95,
                            identities={"owner": user_a.identity_id, "probe": user_b.identity_id},
                            hypothesis=Hypothesis(id=f"hyp_bopla_{mop.operation_id}", rule=Rule(rule_type=RuleType.OWNER_ONLY, resource_type=res_node.label or name.capitalize(), owner_field=owner_field), operation_id=mop.operation_id, confidence=0.95, provenance=Provenance.DOCUMENTED),
                            graph_path=[f"{mop.method} {mop.path} (Mass Assignment on Mutation Persisted)"],
                            control_evidence={"status": m_res.status_code},
                            probe_evidence={"status": m_read.status_code, "persisted_fields": m_persisted},
                            diff_fields=m_persisted,
                            repro_curl=f"curl -X {mop.method} '{m_step.url}' -H 'Authorization: Bearer <USER_A_TOKEN>' -H 'Content-Type: application/json' -d '{json.dumps(injected_fields)}'",
                            reproduction_steps=[f"1. As owner ({user_a.identity_id}) with token <USER_A_TOKEN>, send {mop.method} {mop.path} with {', '.join(m_persisted)}", f"2. Read back {primary.method} {primary.path} and observe persistence."]
                        )
                        findings.append(f)
                        await self._confirm(on_event, f, f"BOPLA Mass Assignment on {mop.method} {mop.path}")
                    elif m_echoed:
                        f = Finding(
                            id=f"fnd_bopla_mut_{uuid.uuid4().hex[:6]}",
                            category="BOPLA",
                            severity="LOW",
                            endpoint=mop.path,
                            method=mop.method,
                            resource_type=res_node.label or name.capitalize(),
                            status=FindingStatus.POTENTIAL,
                            confidence=0.40,
                            identities={"owner": user_a.identity_id, "probe": user_b.identity_id},
                            hypothesis=Hypothesis(id=f"hyp_bopla_{mop.operation_id}", rule=Rule(rule_type=RuleType.OWNER_ONLY, resource_type=res_node.label or name.capitalize(), owner_field=owner_field), operation_id=mop.operation_id, confidence=0.40, provenance=Provenance.DOCUMENTED),
                            graph_path=[f"{mop.method} {mop.path} (Mass Assignment: Echoed in mutation response but not persisted)"],
                            control_evidence={"status": m_res.status_code},
                            probe_evidence={"status": m_read.status_code},
                            diff_fields=m_echoed,
                            repro_curl=f"curl -X {mop.method} '{m_step.url}' -H 'Authorization: Bearer <USER_A_TOKEN>' -H 'Content-Type: application/json' -d '{json.dumps(injected_fields)}'",
                            reproduction_steps=[f"1. Send {mop.method} {mop.path} with {', '.join(m_echoed)}", f"2. Fields echoed but not persisted."]
                        )
                        findings.append(f)
                        await self._emit(on_event, "log", f"[POTENTIAL] BOPLA on {mop.method} {mop.path}: fields echoed but not persisted", "C", f.model_dump())

            # Part B - Excessive data exposure (passive, zero extra requests)
            op_map = {op.operation_id: op for op in operations}
            seen_exposure_keys = set()
            sensitive_patterns = ["password", "hash", "secret", "token", "ssn", "api_key", "private_key", "internal"]

            def _extract_kv(data: Any) -> List[Tuple[str, Any]]:
                items = []
                if isinstance(data, dict):
                    for k, v in data.items():
                        items.append((k, v))
                        if isinstance(v, (dict, list)):
                            items.extend(_extract_kv(v))
                elif isinstance(data, list):
                    for elem in data:
                        if isinstance(elem, (dict, list)):
                            items.extend(_extract_kv(elem))
                return items

            for (step, res) in recorded_responses:
                op = op_map.get(step.operation_id)
                if not op or not (200 <= res.status_code < 300) or not isinstance(res.body, (dict, list)):
                    continue

                res_code_str = str(res.status_code)
                schema = (
                    op.response_schemas.get(res_code_str)
                    or op.response_schemas.get("default")
                    or next((s for c, s in op.response_schemas.items() if c.startswith("2")), None)
                )

                check_key = f"Excessive Data Exposure: {op.method} {op.path}"
                if not schema:
                    if check_key not in [s.resource for s in self.coverage.skipped]:
                        self.coverage.skipped.append(ResourceSkip(resource=check_key, reason=f"no documented response schema for HTTP {res.status_code}"))
                    continue

                if check_key not in self.coverage.bopla_operations_found:
                    self.coverage.bopla_operations_found.append(check_key)
                if check_key not in self.coverage.bopla_operations_tested:
                    self.coverage.bopla_operations_tested.append(check_key)

                doc_props = get_schema_properties(schema)
                for (k, v) in _extract_kv(res.body):
                    if k in doc_props:
                        continue
                    k_lower = k.lower()
                    if any(pat in k_lower for pat in sensitive_patterns):
                        finding_key = (op.operation_id, k)
                        if finding_key in seen_exposure_keys:
                            continue
                        seen_exposure_keys.add(finding_key)
                        masked = "***"
                        f = Finding(
                            id=f"fnd_bopla_exp_{uuid.uuid4().hex[:6]}",
                            category="BOPLA",
                            severity="MEDIUM",
                            endpoint=op.path,
                            method=op.method,
                            resource_type="ObjectProperty",
                            status=FindingStatus.CONFIRMED,
                            confidence=0.90,
                            identities={"owner": user_a.identity_id, "probe": step.identity_id},
                            hypothesis=Hypothesis(
                                id=f"hyp_bopla_{op.operation_id}_{k}",
                                rule=Rule(rule_type=RuleType.OWNER_ONLY, resource_type="ObjectProperty", owner_field=k),
                                operation_id=op.operation_id,
                                confidence=0.90,
                                provenance=Provenance.DOCUMENTED
                            ),
                            graph_path=[f"{op.method} {op.path} (Excessive Data Exposure: Undocumented Sensitive Key '{k}')"],
                            control_evidence={"status": res.status_code},
                            probe_evidence={"undocumented_key": k, "preview": masked, "status": res.status_code},
                            diff_fields=[f"{k}={masked}"],
                            repro_curl=f"curl -X {op.method} '{step.url}' -H 'Authorization: Bearer <TOKEN>'",
                            reproduction_steps=[
                                f"1. Call {op.method} {op.path} with valid credentials.",
                                f"2. Inspect JSON response and observe undocumented sensitive key '{k}' (preview: {masked})."
                            ]
                        )
                        findings.append(f)
                        await self._confirm(on_event, f, f"BOPLA Excessive Data Exposure on {op.method} {op.path}: {k}")

        unique: Dict[tuple, Finding] = {}  # one finding per category/method/endpoint/diff_fields
        for f in findings:
            unique.setdefault((getattr(f, "category", "BOLA"), f.method, f.endpoint, tuple(f.diff_fields)), f)
        return list(unique.values())

    async def _minimize_and_store(self, finding: Finding, setup: PlanStep, probe: PlanStep, client, id_path: str = "id"):
        """Replay setup + probe only; keep the 2-step repro if the leak still reproduces."""
        try:
            s_res = await self.executor.execute_step(setup, client=client)
            h_id = get_path(s_res.body, id_path) if s_res.body else None
            if h_id:
                replay = probe.model_copy(update={"step_id": "min_probe", "json_body": None})
                if (await self.executor.execute_step(replay, client=client)).status_code == 200:
                    finding.minimized_sequence = [f"{setup.method} {setup.path_template} (Setup ID: {h_id})",
                                                  f"{probe.method} {probe.path_template} (Unauthorized Replay)"]
        except Exception:
            finding.minimized_sequence = [f"{setup.method} {setup.path_template}", f"{probe.method} {probe.path_template}"]


async def scan_target(target_profile: Union[str, TargetProfile] = "targets/demo.yaml", enable_mutations: bool = False,
                      budget: int = 30, on_event: Optional[Callable] = None, client: Optional[httpx.AsyncClient] = None,
                      operations: Optional[List[Operation]] = None, enable_bopla: bool = True) -> List[Finding]:
    """Scan an API described by a TargetProfile."""
    from apiguard.engine.auth import AuthRegistry

    profile = load_target_profile(target_profile) if isinstance(target_profile, str) else target_profile
    hosts = set(profile.allowed_hosts) if profile.allowed_hosts else {"localhost", "127.0.0.1"}
    target_host = (urlparse(profile.base_url).hostname or "").lower()
    if target_host not in {h.lower() for h in hosts}:
        raise SecurityViolationError(f"Target host '{target_host}' is not in allowed_hosts: {profile.allowed_hosts}")

    scan_budget = profile.request_budget if profile.request_budget else budget
    executor = SafeExecutor(allowed_hosts=hosts, total_budget=scan_budget, enable_mutations=enable_mutations)

    identities = await AuthRegistry(profile).authenticate_all(client=client)
    owner_name = getattr(profile, "owner", "user_a")
    attacker_name = getattr(profile, "attacker", "user_b")
    user_a = identities.get(owner_name)
    user_b = identities.get(attacker_name)
    if not user_a or not user_b:
        pair = list(identities.values())[:2]
        if len(pair) < 2:
            raise ValueError(f"TargetProfile must define owner '{owner_name}' and attacker '{attacker_name}' identities")
        user_a, user_b = pair[0], pair[1]

    admin_name = getattr(profile, "admin", "admin")
    admin_user = identities.get(admin_name) if admin_name else None

    scanner = GraphGuidedScanner(executor=executor, base_url=profile.base_url, target_profile=profile)
    return await scanner.run_scan(operations=profile.load_operations() if operations is None else operations, user_a=user_a, user_b=user_b,
                                  admin_user=admin_user, enable_mutations=enable_mutations, enable_bopla=enable_bopla, on_event=on_event, client=client)

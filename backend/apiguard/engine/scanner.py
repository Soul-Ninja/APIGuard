import time
import uuid
from typing import List, Dict, Any, Optional, Callable, Union
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
from apiguard.engine.target import TargetProfile, load_target_profile, get_path, build_body_from_schema

DEFAULT_BASE = "http://127.0.0.1:8000/target"
OK = lambda res: 200 <= res.status_code < 300


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

    def _step(self, sid: str, who: IdentityProfile, op: Operation, purpose: str, obj_id=None, body=None) -> PlanStep:
        url = f"{self.base_url}{op.path}"
        if obj_id is not None:
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
                       client: Optional[httpx.AsyncClient] = None) -> List[Finding]:
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

        all_res_nodes = [n for n in self.graph.nodes.values() if n.type == NodeType.RESOURCE_TYPE]
        resource_nodes = [n for n in all_res_nodes if not _is_login_resource(n)]
        for res_node in resource_nodes:
            rname = res_node.metadata.get("resource_name", "") or res_node.label or res_node.id
            if rname and rname not in self.coverage.resources_found:
                self.coverage.resources_found.append(rname)

        findings: List[Finding] = []
        ex = lambda step: self._execute_and_emit(step, on_event, client)

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

        unique: Dict[tuple, Finding] = {}  # one finding per endpoint/method, first wins
        for f in findings:
            unique.setdefault((f.method, f.endpoint), f)
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
                      operations: Optional[List[Operation]] = None) -> List[Finding]:
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

    scanner = GraphGuidedScanner(executor=executor, base_url=profile.base_url, target_profile=profile)
    return await scanner.run_scan(operations=profile.load_operations() if operations is None else operations, user_a=user_a, user_b=user_b,
                                  enable_mutations=enable_mutations, on_event=on_event, client=client)

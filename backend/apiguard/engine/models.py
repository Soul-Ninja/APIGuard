from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class Provenance(str, Enum):
    DOCUMENTED = "documented"
    SCHEMA = "schema"
    HEURISTIC = "heuristic"
    PROPAGATED = "propagated"
    OBSERVED = "observed"

class NodeType(str, Enum):
    OPERATION = "operation"
    RESOURCE_TYPE = "resource_type"
    IDENTIFIER = "identifier"
    IDENTITY = "identity"
    EVIDENCE = "evidence"

class EdgeType(str, Enum):
    OPERATES_ON = "OPERATES_ON"
    PRODUCES = "PRODUCES"
    CONSUMES = "CONSUMES"
    REFERENCES = "REFERENCES"
    NESTED_UNDER = "NESTED_UNDER"
    OBSERVED_ACCESS = "OBSERVED_ACCESS"
    DENIED_ACCESS = "DENIED_ACCESS"
    SUSPECTS_POLICY = "SUSPECTS_POLICY"
    SUPPORTED_BY = "SUPPORTED_BY"

class PolicyResult(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"

class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POTENTIAL = "potential"
    INCONCLUSIVE = "inconclusive"
    NOT_REPRODUCIBLE = "not_reproducible"
    REJECTED = "rejected"

class RuleType(str, Enum):
    AUTH_REQUIRED = "auth_required"
    OWNER_ONLY = "owner_only"
    PARENT_ACCESS = "parent_access"

class Rule(BaseModel):
    rule_type: RuleType
    resource_type: str
    owner_field: Optional[str] = "owner_id"
    parent_type: Optional[str] = None
    via_field: Optional[str] = None
    target_operation_id: Optional[str] = None

class Hypothesis(BaseModel):
    id: str
    rule: Rule
    operation_id: str
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: Provenance
    status: str = "candidate"  # "candidate" | "validated" | "contradicted"
    supporting_observations: List[str] = []
    contradicting_observations: List[str] = []

class IdentityProfile(BaseModel):
    identity_id: str
    username: str = ""
    password: str = ""
    role: str = "customer"
    token: Optional[str] = None
    expired_token: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)

    def get_auth_headers(self) -> Dict[str, str]:
        h = dict(self.headers) if self.headers else {}
        if self.token and "Authorization" not in h:
            h["Authorization"] = f"Bearer {self.token}"
        return h

class ResourceOwnership(BaseModel):
    resource_type: str
    resource_id: str
    owner_identity_id: str

class Operation(BaseModel):
    id: str
    method: str
    path: str
    operation_id: str
    path_params: List[str] = []
    query_params: List[str] = []
    request_schema_ref: Optional[str] = None
    response_schema_refs: Dict[str, str] = {}
    security_schemes: List[str] = []
    tags: List[str] = []
    summary: Optional[str] = None
    is_public: bool = False
    request_schema: Optional[Dict[str, Any]] = None
    response_schemas: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

class GraphNode(BaseModel):
    id: str
    label: str
    type: NodeType
    metadata: Dict[str, Any] = {}

class GraphEdge(BaseModel):
    from_node: str
    to_node: str
    type: EdgeType
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: Provenance
    observation_ids: List[str] = []

class PlanStep(BaseModel):
    step_id: str
    identity_id: str
    operation_id: str
    method: str
    path_template: str
    url: str
    headers: Dict[str, str] = {}
    json_body: Optional[Dict[str, Any]] = None
    expected_status: Optional[int] = None
    purpose: str = "probe_adversary"  # "setup" | "control_owner" | "probe_adversary"
    cleanup: bool = False
    cleanup_operation_id: Optional[str] = None
    cleanup_url: Optional[str] = None

class ExecutionResult(BaseModel):
    step_id: str
    operation_id: str
    identity_id: str
    method: str
    url: str
    status_code: int
    duration_ms: float
    sanitized_headers: Dict[str, str]
    body: Any
    correlation_id: str
    error: Optional[str] = None

class ScanEvent(BaseModel):
    event_id: str
    scan_id: str
    timestamp: float
    event_type: str  # "log" | "step_started" | "step_completed" | "finding_confirmed" | "scan_completed"
    phase: Optional[str] = None
    message: str
    data: Optional[Dict[str, Any]] = None

class Finding(BaseModel):
    id: str
    category: str = "BOLA"
    endpoint: str
    method: str
    resource_type: str
    status: FindingStatus
    confidence: float
    severity: str
    identities: Dict[str, str]  # {"owner": "user_a", "probe": "user_b"}
    hypothesis: Hypothesis
    graph_path: List[str]
    control_evidence: Dict[str, Any]
    probe_evidence: Dict[str, Any]
    diff_fields: List[str]
    repro_curl: str
    reproduction_steps: List[str] = []
    remediation: Optional[str] = None
    minimized_sequence: List[str] = []

class ResourceSkip(BaseModel):
    resource: str
    reason: str

class ScanCoverage(BaseModel):
    resources_found: List[str] = Field(default_factory=list)
    resources_tested: List[str] = Field(default_factory=list)
    skipped: List[ResourceSkip] = Field(default_factory=list)
    admin_operations_found: List[str] = Field(default_factory=list)
    admin_operations_tested: List[str] = Field(default_factory=list)
    bopla_operations_found: List[str] = Field(default_factory=list)
    bopla_operations_tested: List[str] = Field(default_factory=list)
    auth_operations_found: List[str] = Field(default_factory=list)
    auth_operations_tested: List[str] = Field(default_factory=list)


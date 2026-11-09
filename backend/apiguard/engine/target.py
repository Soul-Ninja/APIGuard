import os
import re
import fnmatch
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import yaml
from pydantic import BaseModel, Field

BUNDLED_DEMO_PATH = (Path(__file__).resolve().parent.parent / "targets" / "demo.yaml").resolve()


def expand_env_vars(data: Any) -> Any:
    """Recursively expands ${ENV_VAR} syntax in profile strings; errors if unset."""
    if isinstance(data, str):
        def repl(match):
            var_name = match.group(1)
            if var_name not in os.environ:
                raise ValueError(f"Environment variable '{var_name}' is unset")
            return os.environ[var_name]
        return re.sub(r"\$\{([A-Za-z0-9_]+)\}", repl, data)
    elif isinstance(data, dict):
        return {expand_env_vars(k): expand_env_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [expand_env_vars(item) for item in data]
    return data


def resolve_file_path(path_str: str) -> Path:
    """
    Resolves a file path relative to current working directory,
    or APIGuard project root, or backend root.
    """
    p = Path(path_str)
    if p.is_file():
        return p.resolve()

    # Try relative to repo root (where backend/ and targets/ live)
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    candidate = repo_root / path_str
    if candidate.is_file():
        return candidate.resolve()

    backend_root = Path(__file__).resolve().parent.parent.parent
    candidate_backend = backend_root / path_str
    if candidate_backend.is_file():
        return candidate_backend.resolve()

    # Bundled demo profiles ship inside the package (apiguard/targets/)
    candidate_pkg = Path(__file__).resolve().parent.parent / path_str
    if candidate_pkg.is_file():
        return candidate_pkg.resolve()

    return p.resolve()


def get_path(data: Any, path: str) -> Any:
    """
    Extracts a value from a nested dict using a dotted path.
    e.g. get_path(body, "id") or get_path(body, "data.projectId")
    Returns None if missing, empty, or if data is not a dict.
    """
    if not isinstance(data, dict) or not path:
        return None
    parts = path.split(".")
    curr: Any = data
    for part in parts:
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        else:
            return None
    return curr


def build_body_from_schema(schema: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Builds a minimal create request body from an OpenAPI JSON schema.
    Uses required fields, with simple type defaults:
      - string: "apiguard-test"
      - integer/number: 1
      - boolean: True
      - enum: first enum value
      - array: []
      - object: {}
    If required is omitted or empty, falls back to all top-level properties.
    """
    if not schema or not isinstance(schema, dict):
        return {}

    props = schema.get("properties", {})
    required = schema.get("required")

    target_fields = required if (required is not None and len(required) > 0) else list(props.keys())

    body: Dict[str, Any] = {}
    for field_name in target_fields:
        field_schema = props.get(field_name, {})
        if not isinstance(field_schema, dict):
            field_schema = {}

        if "enum" in field_schema and field_schema["enum"]:
            body[field_name] = field_schema["enum"][0]
        else:
            ftype = field_schema.get("type", "string")
            if ftype == "string":
                body[field_name] = "apiguard-test"
            elif ftype in ("integer", "number"):
                body[field_name] = 1
            elif ftype == "boolean":
                body[field_name] = True
            elif ftype == "array":
                body[field_name] = []
            elif ftype == "object":
                body[field_name] = {}
            else:
                body[field_name] = "apiguard-test"

    return body


class LoginConfig(BaseModel):
    path: str = "/auth/login"
    body_template: Dict[str, Any] = Field(default_factory=lambda: {"username": "{username}", "password": "{password}"})
    token_path: str = "token"
    user_id_path: str = "user_id"


class IdentityConfig(BaseModel):
    name: str
    role: str = "customer"
    headers: Dict[str, str] = Field(default_factory=dict)
    identity_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None


class ResourceOverride(BaseModel):
    id_path: str = "id"
    body: Optional[Dict[str, Any]] = None
    sensitive_fields: List[str] = Field(default_factory=list)
    owner_field: str = "owner_id"


class TargetProfile(BaseModel):
    base_url: str
    spec_path: Optional[str] = "demo_spec.yaml"
    identities: List[IdentityConfig] = Field(default_factory=list)
    login: Optional[LoginConfig] = None
    resources: Dict[str, ResourceOverride] = Field(default_factory=dict)
    admin_operations: List[str] = Field(default_factory=list)
    admin: Optional[str] = "admin"
    allowed_hosts: List[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    request_budget: int = 30
    owner: str = "user_a"
    attacker: str = "user_b"
    is_demo: bool = False

    def get_resource_override(self, resource_name: str) -> Optional[ResourceOverride]:
        if not resource_name:
            return None
        res_lower = resource_name.lower()
        for k, v in self.resources.items():
            if k.lower() == res_lower:
                return v
        return None

    def get_identity(self, name: str) -> Optional[IdentityConfig]:
        for ident in self.identities:
            if ident.name == name:
                return ident
        return None

    def load_operations(self):
        from apiguard.engine.spec import OpenAPIParser, DEMO_SPEC_YAML
        if not self.spec_path:
            if self.is_demo:
                parser = OpenAPIParser(DEMO_SPEC_YAML)
                return parser.extract_operations()
            raise ValueError("spec_path is required for non-demo profiles")
        resolved = resolve_file_path(self.spec_path)
        if not resolved.is_file():
            if self.is_demo:
                parser = OpenAPIParser(DEMO_SPEC_YAML)
                return parser.extract_operations()
            raise FileNotFoundError(f"OpenAPI spec file not found: {self.spec_path}")
        with open(resolved, "r", encoding="utf-8") as f:
            raw_spec = f.read()
        parser = OpenAPIParser(raw_spec)
        return parser.extract_operations()

    @classmethod
    def from_yaml(cls, path_or_content: Union[str, Path]) -> "TargetProfile":
        is_demo_file = False
        if isinstance(path_or_content, Path) or (isinstance(path_or_content, str) and (path_or_content.endswith((".yaml", ".yml")) or "\n" not in path_or_content)):
            resolved = resolve_file_path(str(path_or_content))
            try:
                is_demo_file = (resolved.resolve() == BUNDLED_DEMO_PATH)
            except Exception:
                is_demo_file = False
            with open(resolved, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        else:
            data = yaml.safe_load(str(path_or_content))

        data = expand_env_vars(data or {})
        # Always set is_demo based on whether the file is the bundled demo; ignore user is_demo key
        data["is_demo"] = is_demo_file
        return cls(**data)


def load_target_profile(path_or_obj: Union[str, Path, TargetProfile, Dict[str, Any]]) -> TargetProfile:
    if isinstance(path_or_obj, TargetProfile):
        return path_or_obj
    if isinstance(path_or_obj, dict):
        d = dict(expand_env_vars(path_or_obj))
        d["is_demo"] = False
        return TargetProfile(**d)
    return TargetProfile.from_yaml(path_or_obj)


def is_admin_operation(op: Any, profile: Optional[TargetProfile] = None) -> bool:
    """
    Determines if an OpenAPI operation is admin-only (OWASP API5 - BFLA):
    1. Listed in profile.admin_operations (as operationIds or "METHOD /path" globs, or path globs)
    2. Path contains an /admin segment
    3. Operation has the OpenAPI tag "admin"
    """
    # Rule 1: TargetProfile admin_operations
    if profile and profile.admin_operations:
        op_id = getattr(op, "operation_id", "") or ""
        method = getattr(op, "method", "") or ""
        path = getattr(op, "path", "") or ""
        method_path = f"{method} {path}"

        for pattern in profile.admin_operations:
            p = pattern.strip()
            # Match operation_id (exact or glob)
            if op_id and (p == op_id or fnmatch.fnmatch(op_id.lower(), p.lower())):
                return True
            # Match "METHOD /path" glob
            if fnmatch.fnmatch(method_path.lower(), p.lower()):
                return True
            # Match path glob if pattern starts with /
            if p.startswith("/") and fnmatch.fnmatch(path.lower(), p.lower()):
                return True

    # Rule 2: Path has an /admin segment
    path = getattr(op, "path", "") or ""
    segments = [s.lower() for s in path.split("/") if s]
    if "admin" in segments:
        return True

    # Rule 3: OpenAPI tag "admin"
    tags = getattr(op, "tags", []) or []
    if any(t.lower() == "admin" for t in tags):
        return True

    return False

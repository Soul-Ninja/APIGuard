import re
import yaml
import json
from typing import Dict, Any, List, Tuple
from openapi_spec_validator import validate
from apiguard.engine.models import Operation

DEMO_SPEC_YAML = """
openapi: 3.0.3
info:
  title: Enterprise Project & Billing Services API
  version: 1.0.0
  description: Multi-tenant project and invoicing management API
paths:
  /auth/login:
    post:
      summary: Authenticate identity and obtain bearer token
      operationId: login
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '200':
          description: Login successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AuthToken'

  /projects:
    post:
      summary: Create a new project resource
      operationId: createProject
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateProjectInput'
      responses:
        '201':
          description: Project created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Project'

  /projects/{project_id}:
    get:
      summary: Get project details
      operationId: getProjectById
      security:
        - bearerAuth: []
      parameters:
        - name: project_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Project retrieved
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Project'
        '403':
          description: Forbidden
        '404':
          description: Project not found

    patch:
      summary: Update project properties
      operationId: updateProject
      security:
        - bearerAuth: []
      parameters:
        - name: project_id
          in: path
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UpdateProjectInput'
      responses:
        '200':
          description: Updated project
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Project'

    delete:
      summary: Delete project resource
      operationId: deleteProject
      security:
        - bearerAuth: []
      parameters:
        - name: project_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Deleted successfully

  /projects/{project_id}/export:
    get:
      summary: Export financial and billing data for a project
      operationId: exportProjectBilling
      security:
        - bearerAuth: []
      parameters:
        - name: project_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Project export payload
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ProjectExport'

  /projects/{project_id}/summary:
    get:
      summary: Get brief public project stats (verifier trap)
      operationId: getProjectSummary
      security:
        - bearerAuth: []
      parameters:
        - name: project_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Public summary stats

  /projects/{project_id}/members:
    get:
      summary: Get project members (unimplemented route returning 404)
      operationId: getProjectMembers
      security:
        - bearerAuth: []
      parameters:
        - name: project_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Project member list

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer

  schemas:
    LoginRequest:
      type: object
      required:
        - username
        - password
      properties:
        username:
          type: string
        password:
          type: string

    AuthToken:
      type: object
      required:
        - token
      properties:
        token:
          type: string
        user_id:
          type: string
        role:
          type: string

    CreateProjectInput:
      type: object
      required:
        - name
      properties:
        name:
          type: string
        confidential_data:
          type: string
        budget:
          type: string

    UpdateProjectInput:
      type: object
      properties:
        name:
          type: string
        budget:
          type: string

    Project:
      type: object
      required:
        - id
        - owner_id
        - name
      properties:
        id:
          type: string
        owner_id:
          type: string
        owner_email:
          type: string
        name:
          type: string
        confidential_data:
          type: string
        budget:
          type: string
        billing_card:
          type: string

    ProjectExport:
      type: object
      required:
        - export_id
        - project_id
      properties:
        export_id:
          type: string
        project_id:
          type: string
        owner_email:
          type: string
        financial_payload:
          type: object
"""

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


class OpenAPIParser:
    """Parses OpenAPI 3.x (YAML or JSON) and resolves local $refs."""

    def __init__(self, raw_spec: str):
        self.spec_dict = json.loads(raw_spec) if raw_spec.strip().startswith("{") else yaml.safe_load(raw_spec)
        validate(self.spec_dict)
        self.resolved_spec = self._resolve_refs(self.spec_dict, self.spec_dict)

    def _resolve_refs(self, element: Any, root: Dict[str, Any]) -> Any:
        if isinstance(element, dict):
            ref = element.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/"):
                target = root
                for part in ref[2:].split("/"):
                    target = target.get(part, {})
                return self._resolve_refs(target, root)
            return {k: self._resolve_refs(v, root) for k, v in element.items()}
        if isinstance(element, list):
            return [self._resolve_refs(item, root) for item in element]
        return element

    @staticmethod
    def _json_schema(obj: Any) -> Dict[str, Any]:
        """The application/json schema of a requestBody or response object ({} if none)."""
        content = obj.get("content", {}).get("application/json", {}) if isinstance(obj, dict) else {}
        return content.get("schema", {})

    def extract_operations(self) -> List[Operation]:
        operations = []
        root_security = self.spec_dict.get("security")
        for path, item in self.spec_dict.get("paths", {}).items():
            if not isinstance(item, dict):
                continue
            for method, op in item.items():
                if method.lower() not in HTTP_METHODS:
                    continue
                op_id = op.get("operationId") or f"{method.lower()}_{re.sub(r'[^a-zA-Z0-9]', '_', path)}"
                resolved_op = self.resolved_spec["paths"][path].get(method, {})
                resolved_responses = {}
                for code, resp in resolved_op.get("responses", {}).items():
                    s = self._json_schema(resp)
                    if s:
                        resolved_responses[str(code)] = s

                op_security = op.get("security")
                if op_security is not None:
                    is_public = (len(op_security) == 0)
                else:
                    is_public = (root_security is None or len(root_security) == 0)

                active_sec = op_security if op_security is not None else (root_security or [])
                raw_responses = resolved_op.get("responses") or op.get("responses") or {}
                operations.append(Operation(
                    id=op_id,
                    method=method.upper(),
                    path=path,
                    operation_id=op_id,
                    path_params=re.findall(r"\{([a-zA-Z0-9_]+)\}", path),
                    query_params=[p.get("name") for p in op.get("parameters", []) if isinstance(p, dict) and p.get("in") == "query"],
                    request_schema_ref=self._json_schema(op.get("requestBody", {})).get("$ref"),
                    response_schema_refs={str(code): ref for code, r in op.get("responses", {}).items()
                                          if (ref := self._json_schema(r).get("$ref"))},
                    security_schemes=[name for req in active_sec if isinstance(req, dict) for name in req],
                    tags=op.get("tags", []),
                    summary=op.get("summary"),
                    is_public=is_public,
                    deprecated=bool(op.get("deprecated", False)),
                    documented_status_codes=[str(c) for c in raw_responses.keys()],
                    request_schema=self._json_schema(resolved_op.get("requestBody", {})) or None,
                    response_schemas=resolved_responses,
                ))
        return operations

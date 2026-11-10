from typing import Optional, Dict, Any
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel
from apiguard.target.data import TOKEN_TO_USER, PROJECTS_STORE, SEEDED_USERS, reset_db
from apiguard.target.config import get_target_config

target_app = FastAPI(title="Vulnerable Target Service", version="1.0.0")

class LoginInput(BaseModel):
    username: str
    password: str

class ProjectCreateInput(BaseModel):
    model_config = {"extra": "allow"}
    name: str
    confidential_data: Optional[str] = "Confidential Data"
    budget: Optional[str] = "$50,000"

class ProjectUpdateInput(BaseModel):
    name: Optional[str] = None
    budget: Optional[str] = None

def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization Header")
    token = authorization.replace("Bearer ", "").strip()
    user = TOKEN_TO_USER.get(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Bearer Token")
    return user

@target_app.post("/auth/login")
def login(creds: LoginInput):
    # REAL credential validation
    user = SEEDED_USERS.get(creds.username)
    if not user or user["password"] != creds.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    return {
        "token": user["token"],
        "user_id": user["id"],
        "role": user["role"]
    }

@target_app.post("/projects", status_code=status.HTTP_201_CREATED)
def create_project(data: ProjectCreateInput, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    cfg = get_target_config()
    project_id = f"proj_{len(PROJECTS_STORE) + 42}"
    record = {
        "id": project_id,
        "owner_id": user["id"],
        "created_by": user["id"],
        "owner_email": user["username"],
        "name": data.name,
        "confidential_data": data.confidential_data,
        "budget": data.budget,
        "billing_card": "**** **** **** 4242",
        "created_at": "2026-10-21T22:00:00Z"
    }
    if cfg.defect_mass_assign and not cfg.patched_mode:
        extra = getattr(data, "__pydantic_extra__", None) or getattr(data, "model_extra", None) or {}
        if "owner_id" in extra:
            record["owner_id"] = extra["owner_id"]
        if "role" in extra:
            record["role"] = extra["role"]
        if "is_admin" in extra:
            record["is_admin"] = extra["is_admin"]

    PROJECTS_STORE[project_id] = record
    return record

@target_app.get("/projects/{project_id}")
def get_project(project_id: str, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    cfg = get_target_config()

    project = PROJECTS_STORE.get(project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    res = dict(project)
    if cfg.defect_exposure and not cfg.patched_mode:
        res["password_hash"] = "pbkdf2_sha256$260000$secret_hash_value_xyz"

    # Legitimate role exemptions (Admin & Support may read any project)
    if user["role"] in {"admin", "support"}:
        return res

    # Check ownership unless Defect A is enabled AND not in patched mode
    is_vulnerable = cfg.defect_a and not cfg.patched_mode
    if not is_vulnerable:
        # SECURE: enforce ownership
        if project["owner_id"] != user["id"] and project.get("created_by") != user["id"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: You do not own this project")

    return res

@target_app.get("/projects/{project_id}/export")
def export_project(project_id: str, authorization: Optional[str] = Header(None)):
    """
    KEY DEMO MOMENT:
    Primary GET /projects/{id} is secure, but this graph-adjacent export leaks Aman's billing data!
    """
    user = get_current_user(authorization)
    cfg = get_target_config()

    project = PROJECTS_STORE.get(project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    if user["role"] == "admin":
        return {
            "export_id": f"exp_{project_id}",
            "project_id": project_id,
            "owner_email": project["owner_email"],
            "financial_payload": {"budget": project["budget"], "billing": project["billing_card"]}
        }

    # DEFECT B: Leaks unless patched or defect_b disabled
    is_vulnerable = cfg.defect_b and not cfg.patched_mode
    if not is_vulnerable:
        if project["owner_id"] != user["id"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: You do not own this project export")

    return {
        "export_id": f"exp_{project_id}",
        "project_id": project_id,
        "owner_email": project["owner_email"],
        "financial_payload": {
            "budget": project["budget"],
            "billing": project["billing_card"]
        }
    }

@target_app.patch("/projects/{project_id}")
def update_project(project_id: str, data: ProjectUpdateInput, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    cfg = get_target_config()

    project = PROJECTS_STORE.get(project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    is_vulnerable = cfg.defect_c and not cfg.patched_mode
    if not is_vulnerable:
        if project["owner_id"] != user["id"] and user["role"] != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: Cannot mutate another user's project")

    if data.name:
        project["name"] = data.name
    if data.budget:
        project["budget"] = data.budget

    return project

@target_app.delete("/projects/{project_id}")
def delete_project(project_id: str, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    project = PROJECTS_STORE.get(project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    # Strictly secure ownership check
    if project["owner_id"] != user["id"] and user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: Cannot delete project")

    del PROJECTS_STORE[project_id]
    return {"status": "deleted", "id": project_id}

# ========================
# VERIFIER TRAPS
# ========================
@target_app.get("/projects/{project_id}/summary")
def get_project_summary(project_id: str, authorization: Optional[str] = Header(None)):
    """Trap 1: Returns 200 with empty body for non-owners (must NOT be confirmed BOLA)"""
    user = get_current_user(authorization)
    project = PROJECTS_STORE.get(project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if project["owner_id"] != user["id"] and user["role"] != "admin":
        return {} # Empty body trap
    return {"status": "active", "task_count": 12}

@target_app.get("/projects/{project_id}/audit-log")
def get_project_audit_log(project_id: str, authorization: Optional[str] = Header(None)):
    """Decoy: returns 404 for non-owners (must NOT be flagged). Not listed in the demo OpenAPI spec, so the
    spec-driven scanner never visits it; it is kept for manual testing."""
    user = get_current_user(authorization)
    project = PROJECTS_STORE.get(project_id)
    if not project or (project["owner_id"] != user["id"] and user["role"] != "admin"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    return {"events": ["created", "viewed"]}

# ========================
# ADMIN / BFLA ENDPOINTS
# ========================
@target_app.get("/admin/users")
def get_admin_users(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    cfg = get_target_config()

    # BFLA DEFECT: If defect_bfla is enabled and not patched, role check is skipped!
    is_vulnerable = cfg.defect_bfla and not cfg.patched_mode
    if not is_vulnerable:
        if user.get("role") != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: Admin role required")

    return [
        {"id": "usr_admin_001", "username": "admin@corp.internal", "role": "admin"},
        {"id": "usr_aman_101", "username": "aman@acme.corp", "role": "customer"},
        {"id": "usr_taaran_202", "username": "taaran@adversary.io", "role": "customer"}
    ]

@target_app.post("/reset")
def reset_endpoint():
    reset_db()
    return {"status": "reset_success"}

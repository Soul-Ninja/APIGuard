import copy
from typing import Dict, Any

SEEDED_USERS = {
    "aman@acme.corp": {
        "id": "usr_aman_101",
        "username": "aman@acme.corp",
        "password": "password_aman_123",
        "role": "customer",
        "token": "tok_live_aman_8921"
    },
    "taaran@adversary.io": {
        "id": "usr_taaran_202",
        "username": "taaran@adversary.io",
        "password": "password_taaran_456",
        "role": "customer",
        "token": "tok_live_taaran_9934"
    },
    "admin@corp.internal": {
        "id": "usr_admin_001",
        "username": "admin@corp.internal",
        "password": "password_admin_999",
        "role": "admin",
        "token": "tok_live_admin_1111"
    },
    "support@corp.internal": {
        "id": "usr_support_002",
        "username": "support@corp.internal",
        "password": "password_support_777",
        "role": "support",
        "token": "tok_live_support_2222"
    }
}

SEEDED_PROJECTS = {
    "proj_42": {
        "id": "proj_42",
        "owner_id": "usr_aman_101",
        "owner_email": "aman@acme.corp",
        "name": "Project Aegis Quantum",
        "confidential_data": "QNTM-SECRET-PROD-KEY-9981",
        "budget": "$240,000",
        "billing_card": "**** **** **** 4242",
        "created_at": "2026-10-21T21:00:00Z"
    }
}

TOKEN_TO_USER: Dict[str, Dict[str, Any]] = {}
PROJECTS_STORE: Dict[str, Dict[str, Any]] = {}

def reset_db():
    global TOKEN_TO_USER, PROJECTS_STORE
    TOKEN_TO_USER.clear()
    PROJECTS_STORE.clear()

    # Repopulate
    for user in SEEDED_USERS.values():
        TOKEN_TO_USER[user["token"]] = user

    PROJECTS_STORE.update(copy.deepcopy(SEEDED_PROJECTS))

reset_db()

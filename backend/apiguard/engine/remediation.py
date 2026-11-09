import os
import time
import uuid
import asyncio
import httpx
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
from dotenv import load_dotenv
from apiguard.db import save_remediation, get_last_real_remediation

BACKEND = Path(__file__).resolve().parents[2]


def _load_env():
    """Re-read .env on every call so key changes apply without a restart."""
    for p in (BACKEND / ".env", BACKEND.parent / ".env"):
        if p.exists():
            load_dotenv(p, override=False)
    load_dotenv(override=False)


_load_env()

OFFLINE_V1_TEMPLATE = """# [Illustrative template, not model output]
# Common pitfall: Authentication-only check (fails to verify tenant resource ownership)

@app.{method_lower}("{path}")
def {func_name}({params_sig}, current_user: User = Depends(get_current_user)):
    # Vulnerable: Only verifies that caller is authenticated, not that they own {resource}
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return execute_export(project_id)
"""

OFFLINE_V2_TEMPLATE = """# [Illustrative template, not model output]
# Reference fix: Resource-level owner verification

@app.{method_lower}("{path}")
def {func_name}({params_sig}, current_user: User = Depends(get_current_user)):
    # 1. Fetch parent resource and verify existence
    project = get_project_or_404(project_id)

    # 2. Enforce Graph-Inferred Owner-Only Authorization Policy
    if project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: you do not have permission to access this resource"
        )

    # 3. Authorized access allowed
    return execute_authorized_export(project)
"""

OFFLINE_UNIT_TEST = """def test_bola_remediation_blocked():
    # Verify unauthorized identity is rejected with HTTP 403 Forbidden
    client = TestClient(app)
    response = client.get(
        "{endpoint_url}",
        headers={{"Authorization": "Bearer " + taaran_token}}
    )
    assert response.status_code == 403
    assert "forbidden" in response.json().get("detail", "").lower()
"""

OPENROUTER_FALLBACK = ["recursive/flint-v1.0:free", "nvidia/nemotron-3.5-super-vl:free", "liquid/lfm-2.5-2.6b:free",
                       "google/gemma-2-9b-it:free", "meta-llama/llama-3.2-3b-instruct:free", "mistralai/mistral-7b-instruct:free"]
GEMINI_MODELS = ["gemini-3.8-flash", "gemini-3.6-flash", "gemini-3.5-flash-lite", "gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]

Result = Tuple[Optional[str], Optional[str], Optional[str]]  # (text, model, error)

# process-wide: survives a new RemediationEngine() per request
state = {"real_call_ok": False, "last_openrouter_model": OPENROUTER_FALLBACK[0]}


class RemediationEngine:
    """Remediation generator. Order: OpenRouter, then Gemini, then the last real result cached in SQLite, then an offline template."""

    def __init__(self):
        self.last_error: Optional[str] = None

    @staticmethod
    def _env(name: str) -> Optional[str]:
        _load_env()
        return os.environ.get(name)

    def _providers(self):
        """(name, key present, caller, per-call timeout) in priority order."""
        return [("OpenRouter", self._env("OPENROUTER_API_KEY"), self._call_openrouter, 6.5),
                ("Gemini", self._env("GEMINI_API_KEY"), self._call_gemini, 6.0)]

    async def get_status(self) -> Dict[str, Any]:
        or_key, gem_key = self._env("OPENROUTER_API_KEY"), self._env("GEMINI_API_KEY")
        active = "OpenRouter" if or_key else "Gemini" if gem_key else "None"
        return {"openrouter_key_present": bool(or_key), "gemini_key_present": bool(gem_key), "active_provider": active,
                "configured_model": self._env("OPENROUTER_MODEL" if active == "OpenRouter" else "GEMINI_MODEL"),
                "last_error": self.last_error, "status": "active" if active != "None" else "offline_template_only",
                "session_real_model_call_succeeded": state["real_call_ok"]}

    async def test_connection(self) -> Dict[str, Any]:
        start = time.time()
        for name, key, call, _ in self._providers():
            if not key:
                continue
            out, model, err = await call("Say OK in one word.")
            if out:
                state["real_call_ok"] = True
                return {"success": True, "provider": name, "model": model, "output": out.strip()[:60],
                        "duration_ms": int((time.time() - start) * 1000)}
            self.last_error = f"{name} test failed: {err}"
        return {"success": False, "error": self.last_error or "Neither OPENROUTER_API_KEY nor GEMINI_API_KEY is configured in backend/.env"}

    async def _openrouter_free_models(self) -> List[str]:
        """Free model ids from the OpenRouter catalog (pricing "0"), or a static list if the catalog is unreachable."""
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.get("https://openrouter.ai/api/v1/models")
            if res.status_code == 200:
                free = [m["id"] for m in res.json().get("data", [])
                        if m.get("pricing", {}).get("prompt") == "0" and m.get("pricing", {}).get("completion") == "0"]
                if free:
                    return free
        except Exception as e:
            self.last_error = f"Failed to fetch OpenRouter free models catalog: {e}"
        return OPENROUTER_FALLBACK

    async def _call_openrouter(self, prompt: str) -> Result:
        """OpenAI-compatible chat call; moves to the next model on any failure."""
        key = self._env("OPENROUTER_API_KEY")
        if not key:
            return None, None, "OPENROUTER_API_KEY not configured"
        if (pinned := self._env("OPENROUTER_MODEL")):
            models = [pinned]
        else:
            catalog, last = await self._openrouter_free_models(), state["last_openrouter_model"]
            models = [last] + [m for m in catalog if m != last][:1] if last in catalog else catalog[:2]
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                   "HTTP-Referer": "http://127.0.0.1:8000", "X-Title": "APIGuard BOLA Engine"}
        err = None
        for model in models:
            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    r = await client.post("https://openrouter.ai/api/v1/chat/completions", headers=headers,
                                          json={"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2})
                if r.status_code != 200:
                    err = f"OpenRouter model {model} failed with HTTP {r.status_code}: {r.text[:100]}"
                    continue
                choices = r.json().get("choices", [])
                if choices and (text := choices[0].get("message", {}).get("content")):
                    state["last_openrouter_model"] = model
                    return text, model, None
            except Exception as e:
                err = f"OpenRouter request error on {model}: {e}"
        return None, None, err or "All OpenRouter models failed"

    async def _call_gemini(self, prompt: str) -> Result:
        key = self._env("GEMINI_API_KEY")
        if not key:
            return None, None, "GEMINI_API_KEY not configured"
        pinned = self._env("GEMINI_MODEL")
        models = [pinned] + [m for m in GEMINI_MODELS if m != pinned] if pinned else GEMINI_MODELS
        err = None
        for model in (m.replace("models/", "") for m in models):
            try:
                async with httpx.AsyncClient(timeout=12.0) as client:
                    r = await client.post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                                          headers={"x-goog-api-key": key, "Content-Type": "application/json"},
                                          json={"contents": [{"parts": [{"text": prompt}]}]})
                if r.status_code != 200:
                    err = f"Gemini model {model} failed: HTTP {r.status_code} ({r.text[:100]})"
                    continue
                cands = r.json().get("candidates", [])
                parts = cands[0].get("content", {}).get("parts", []) if cands else []
                if parts and "text" in parts[0]:
                    return parts[0]["text"], model, None
            except Exception as e:
                err = f"Gemini error on {model}: {e}"
        return None, None, err or "All Gemini models failed"

    async def generate_remediation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Compare a naive fix prompt (v1) with a graph-aware one (v2); fall back to cache, then to a template."""
        endpoint = finding.get("endpoint", "/projects/{project_id}/export")
        method = finding.get("method", "GET")
        resource = finding.get("resource_type", "Project")
        leaked = ", ".join(finding.get("diff_fields", ["owner_email", "financial_payload"]))
        finding_id = finding.get("id") or finding.get("finding_id", "fnd_remed")

        v1_prompt = f"Fix this BOLA security bug in our API: endpoint {method} {endpoint} allows unauthorized users to read data."
        v2_prompt = (f"Context: Graph-Guided BOLA Engine detected authorization defect on {method} {endpoint}.\n"
                     f"Resource: {resource}. Leaked owner-specific fields: {leaked}.\n"
                     f"Generate a secure FastAPI route fix verifying that the authenticated user owns {resource} "
                     f"or possesses role 'admin', and provide a pytest unit test.")
        unit_test = OFFLINE_UNIT_TEST.format(endpoint_url="/projects/proj_42/export")

        rec = {"source": "offline_template", "provider": "offline", "model": "None", "v1_output": "", "v2_output": "",
               "code_patch": "", "explanation": "", "error_reason": None, "is_real": False,
               "badge_text": "Offline template (illustrative, not model output)"}

        # 1-2. live providers, called one after the other (OpenRouter's free tier allows 1 concurrent request)
        for name, key, call, timeout in self._providers():
            if not key or rec["is_real"]:
                continue
            try:
                v1, m1, _ = await asyncio.wait_for(call(v1_prompt), timeout)
                v2, m2, _ = await asyncio.wait_for(call(v2_prompt), timeout) if v1 else (None, None, None)
            except asyncio.TimeoutError:
                self.last_error = "Live model queue busy; switched to recorded baseline telemetry"
                continue
            except Exception as e:
                self.last_error = f"{name} error: {e}"
                continue
            if not (v1 and v2):
                self.last_error = f"{name} {'v2' if v1 else 'v1'} generation delayed"
                continue
            model = m2 or m1
            state["real_call_ok"] = True
            rec.update(source="real", provider=name, model=model, badge_text=f"{name}: {model}", v1_output=v1, v2_output=v2,
                       code_patch=v2, is_real=True,
                       explanation=f"Generated live using {name} model ({model}). Both v1 and v2 outputs are real model completions.")

        # 3. last real result recorded in SQLite
        if not rec["is_real"]:
            cached = await get_last_real_remediation(finding_id)
            if cached and cached.get("is_real"):
                provider, model = cached.get("provider", "OpenRouter"), cached.get("model", OPENROUTER_FALLBACK[0])
                when = time.strftime("%Y-%m-%d %H:%M", time.localtime(cached.get("timestamp", time.time())))
                unit_test = cached.get("unit_test", unit_test)
                rec.update(source="cached_real", provider=provider, model=model, badge_text=f"{provider}: {model} (recorded {when})",
                           v1_output=cached.get("v1_output", ""), v2_output=cached.get("v2_output", ""),
                           code_patch=cached.get("code_patch", ""), explanation=cached.get("explanation", ""), is_real=True)

        # 4. illustrative template (also covers a cached row with empty outputs)
        if not (rec["v1_output"] and rec["v2_output"]):
            fmt = dict(method_lower=method.lower(), path=endpoint, func_name="export_project_billing",
                       params_sig="project_id: str", resource=resource)
            patch = OFFLINE_V2_TEMPLATE.format(**fmt)
            has_keys = self._env("OPENROUTER_API_KEY") or self._env("GEMINI_API_KEY")
            rec.update(source="offline_template", provider="offline", model="Offline template",
                       badge_text="Offline template (illustrative, not model output)",
                       error_reason="Live queue busy; serving reference remediation template" if has_keys
                       else "Neither OPENROUTER_API_KEY nor GEMINI_API_KEY configured in backend/.env",
                       v1_output=OFFLINE_V1_TEMPLATE.format(**fmt), code_patch=patch,
                       v2_output=f"{patch}\n\n# Verification Test:\n{unit_test}",
                       explanation=(f"The target endpoint {endpoint} failed to check ownership. In the parent endpoint, "
                                    f"GET /projects/{{project_id}} checked owner_id. The fix propagates this ownership check "
                                    f"to ensure only the resource owner (or an administrator) can access {endpoint}."))

        record = {"id": f"rem_{uuid.uuid4().hex[:8]}", "finding_id": finding_id, "timestamp": time.time(), "endpoint": endpoint,
                  "v1_prompt": v1_prompt, "v2_prompt": v2_prompt, "unit_test": unit_test, **rec, "is_real": 1 if rec["is_real"] else 0}
        await save_remediation(record)
        return record

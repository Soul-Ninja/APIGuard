import httpx
from typing import Dict, Any, Optional, Union
from apiguard.engine.models import IdentityProfile
from apiguard.engine.target import TargetProfile, load_target_profile, get_path

DEMO_PROFILE = "targets/demo.yaml"

# the UI's identity list and the dry-run preview read the demo users from the profile; a missing profile must fail loudly
DEFAULT_CREDENTIALS = {
    i.name: {"identity_id": i.identity_id or i.name, "username": i.username or i.name, "password": i.password or "", "role": i.role}
    for i in load_target_profile(DEMO_PROFILE).identities
}


class AuthRegistry:
    """
    Manages test identities from a TargetProfile.
    Supports dynamic login if profile specifies a login flow,
    or static headers (e.g. pre-issued Bearer tokens, API keys).
    """
    def __init__(self, target: Optional[Union[TargetProfile, str]] = None):
        if isinstance(target, str) and target.startswith(("http://", "https://")):
            self.profile = load_target_profile(DEMO_PROFILE)  # a bare URL means the demo identities against that host
            self.profile.base_url = target
        else:
            self.profile = target if isinstance(target, TargetProfile) else load_target_profile(target or DEMO_PROFILE)
        self.base_url = self.profile.base_url.rstrip("/")

    async def authenticate_all(
        self,
        client: Optional[httpx.AsyncClient] = None
    ) -> Dict[str, IdentityProfile]:
        profiles: Dict[str, IdentityProfile] = {}
        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=5.0)
            should_close = True

        try:
            for ident in self.profile.identities:
                headers = dict(ident.headers) if ident.headers else {}
                token = ident.token

                # If dynamic login is configured and identity provides username & password
                if self.profile.login and ident.username and ident.password:
                    login_body: Dict[str, Any] = {}
                    for k, v in self.profile.login.body_template.items():
                        if isinstance(v, str):
                            login_body[k] = (
                                v.replace("{username}", ident.username)
                                 .replace("{password}", ident.password)
                            )
                        else:
                            login_body[k] = v

                    login_url = f"{self.base_url}{self.profile.login.path}"
                    resp = await client.post(login_url, json=login_body)
                    if resp.status_code != 200:
                        raise RuntimeError(
                            f"Authentication failed for {ident.username} at {login_url}: {resp.status_code} {resp.text}"
                        )

                    data = resp.json() if isinstance(resp.json(), dict) else {}
                    token_path = self.profile.login.token_path or "token"
                    user_id_path = self.profile.login.user_id_path or "user_id"

                    token_val = get_path(data, token_path)
                    if token_val is not None:
                        token = str(token_val)
                    uid_val = get_path(data, user_id_path)
                    identity_id = str(uid_val) if uid_val is not None else (ident.identity_id or ident.name)
                    role = data.get("role", ident.role)

                    if token and "Authorization" not in headers:
                        headers["Authorization"] = f"Bearer {token}"

                    profiles[ident.name] = IdentityProfile(
                        identity_id=identity_id,
                        username=ident.username,
                        password=ident.password,
                        role=role,
                        token=token,
                        headers=headers
                    )
                else:
                    # Static identity with pre-configured headers/token
                    if token and "Authorization" not in headers:
                        headers["Authorization"] = f"Bearer {token}"

                    profiles[ident.name] = IdentityProfile(
                        identity_id=ident.identity_id or ident.name,
                        username=ident.username or ident.name,
                        password=ident.password or "",
                        role=ident.role,
                        token=token,
                        headers=headers
                    )

            return profiles
        finally:
            if should_close:
                await client.aclose()

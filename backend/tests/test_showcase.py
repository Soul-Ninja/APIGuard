import pytest
import sys
import httpx
from apiguard.engine.cli import run_cli_scan
from apiguard.engine.models import FindingStatus
from apiguard.target.data import reset_db
from apiguard.target.config import update_target_config, get_target_config
from apiguard.main import app

@pytest.mark.asyncio
async def test_showcase_cli_rejects_non_demo_profile(capsys, tmp_path):
    # Non-demo profile
    custom_profile = tmp_path / "custom.yaml"
    custom_profile.write_text("""
is_demo: false
base_url: "http://127.0.0.1:8000/target"
allowed_hosts: ["127.0.0.1", "localhost"]
identities:
  - name: user_a
    role: customer
    token: tok_a
  - name: user_b
    role: customer
    token: tok_b
""", encoding="utf-8")

    code = await run_cli_scan(
        dry_run=False,
        profile_path=str(custom_profile),
        showcase=True
    )
    assert code == 2
    captured = capsys.readouterr()
    assert "--showcase is only supported with the bundled demo profile" in captured.err

@pytest.mark.asyncio
async def test_showcase_cli_finds_all_five_checks():
    reset_db()
    # Run showcase scan against in-process target
    code = await run_cli_scan(
        dry_run=False,
        profile_path="backend/apiguard/targets/demo.yaml",
        showcase=True
    )
    assert code == 1

@pytest.mark.asyncio
async def test_showcase_with_patched_mode_clean():
    from apiguard.engine.scanner import scan_target
    from apiguard.engine.target import load_target_profile

    reset_db()
    update_target_config(
        defect_a=False,
        defect_b=True,
        defect_c=False,
        defect_bfla=True,
        defect_mass_assign=True,
        defect_exposure=True,
        defect_auth=True,
        defect_misconfig=True,
        patched_mode=True
    )
    profile = load_target_profile("backend/apiguard/targets/demo.yaml")
    profile.request_budget = 100

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        findings = await scan_target(target_profile=profile, client=client, budget=100)

    # Active findings must be zero
    active_confirmed = [
        f for f in findings
        if f.status == FindingStatus.CONFIRMED and getattr(f, "category", "BOLA") not in ("MISCONFIG", "INVENTORY")
    ]
    assert len(active_confirmed) == 0

@pytest.mark.asyncio
async def test_dashboard_showcase_endpoint_and_status():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        # Enable showcase
        res = await client.post("/api/target/showcase", json={"enabled": True})
        assert res.status_code == 200
        cfg = res.json()["config"]
        assert cfg["defect_bfla"] is True
        assert cfg["defect_mass_assign"] is True
        assert cfg["defect_exposure"] is True
        assert cfg["defect_auth"] is True
        assert cfg["defect_misconfig"] is True

        # Check status endpoint
        st = (await client.get("/api/target/status")).json()
        assert st["defect_bfla"] is True
        assert st["defect_mass_assign"] is True
        assert st["defect_exposure"] is True
        assert st["defect_auth"] is True
        assert st["defect_misconfig"] is True

        # Reset retains flags
        r_reset = await client.post("/api/target/reset")
        assert r_reset.status_code == 200
        st_after_reset = (await client.get("/api/target/status")).json()
        assert st_after_reset["defect_bfla"] is True
        assert st_after_reset["defect_mass_assign"] is True

        # Patch retains flags
        r_patch = await client.post("/api/target/patch", json={"patched": True})
        assert r_patch.status_code == 200
        st_after_patch = (await client.get("/api/target/status")).json()
        assert st_after_patch["patched_mode"] is True
        assert st_after_patch["defect_bfla"] is True
        assert st_after_patch["defect_mass_assign"] is True

        # Disable showcase (restore default)
        res_off = await client.post("/api/target/showcase", json={"enabled": False})
        assert res_off.status_code == 200
        cfg_off = res_off.json()["config"]
        assert cfg_off["defect_b"] is True
        assert cfg_off["defect_bfla"] is False
        assert cfg_off["defect_mass_assign"] is False
        assert cfg_off["defect_exposure"] is False
        assert cfg_off["defect_auth"] is False
        assert cfg_off["defect_misconfig"] is False

@pytest.mark.asyncio
async def test_tokens_never_in_findings_repro_curl():
    from apiguard.engine.scanner import scan_target
    from apiguard.engine.target import load_target_profile

    reset_db()
    update_target_config(
        defect_a=False,
        defect_b=True,
        defect_c=False,
        defect_bfla=True,
        defect_mass_assign=True,
        defect_exposure=True,
        defect_auth=True,
        defect_misconfig=True,
        patched_mode=False
    )
    profile = load_target_profile("backend/apiguard/targets/demo.yaml")
    profile.request_budget = 100

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        findings = await scan_target(target_profile=profile, client=client, budget=100)

    assert len(findings) >= 5
    secret_tokens = ["tok_demo_a", "tok_demo_b", "tok_demo_admin", "dev_secret_jwt", "Bearer tok_"]
    for f in findings:
        for secret in secret_tokens:
            assert secret not in f.repro_curl
            for step in (f.reproduction_steps or []):
                assert secret not in step
        # Placeholder checks
        if "Bearer" in f.repro_curl:
            assert any(p in f.repro_curl for p in ["<USER_A_TOKEN>", "<USER_B_TOKEN>", "<ADMIN_TOKEN>", "<GARBAGE_TOKEN>", "<ALG_NONE_JWT>", "<ALTERED_SIGNATURE_JWT>", "<EXPIRED_TOKEN>"])

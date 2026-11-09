import sys
import asyncio
import argparse
from urllib.parse import urlparse
import httpx
from apiguard.engine.spec import OpenAPIParser, DEMO_SPEC_YAML
from apiguard.engine.graph import ResourceGraph
from apiguard.engine.planner import TestPlanner
from apiguard.engine.executor import SafeExecutor
from apiguard.engine.scanner import GraphGuidedScanner
from apiguard.engine.auth import AuthRegistry
from apiguard.engine.target import load_target_profile, TargetProfile
from apiguard.engine.models import FindingStatus, IdentityProfile
from apiguard.target.data import reset_db
from apiguard.target.config import update_target_config

def main():
    parser = argparse.ArgumentParser(description="APIGuard CLI - Graph-Guided API Authorization Tester")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    scan_parser = subparsers.add_parser("scan", help="Run authorization scan")
    scan_parser.add_argument("--dry-run", action="store_true", help="Print execution plan without sending HTTP requests")
    scan_parser.add_argument("--target", default=None, help="Target base URL")
    scan_parser.add_argument("--mutations", action="store_true", help="Enable mutating tests (PATCH, DELETE)")
    scan_parser.add_argument("--profile", default="targets/demo.yaml", help="Path to TargetProfile YAML file")

    args = parser.parse_args()

    if args.command == "scan":
        code = asyncio.run(run_cli_scan(dry_run=args.dry_run, target_url=args.target, profile_path=args.profile, enable_mutations=args.mutations))
        sys.exit(code)
    else:
        parser.print_help()
        sys.exit(0)

async def run_cli_scan(dry_run: bool, target_url: str = None, profile_path: str = 'targets/demo.yaml', enable_mutations: bool = False) -> int:
    print("=" * 65)
    print("  APIGuard CLI Engine — Graph-Guided BOLA Scanner")
    print("=" * 65)

    try:
        profile = load_target_profile(profile_path)
    except Exception as e:
        print(f"[ERROR] Configuration error: {e}", file=sys.stderr)
        return 2

    if target_url:
        profile.base_url = target_url
    target_url = profile.base_url

    # Check host allowlist
    parsed_host = (urlparse(target_url).hostname or "").lower()
    allowed = {h.lower() for h in profile.allowed_hosts}
    if parsed_host not in allowed:
        print(f"[ERROR] Host '{parsed_host}' is not in allowed_hosts: {profile.allowed_hosts}", file=sys.stderr)
        return 2

    try:
        operations = profile.load_operations()
    except Exception as e:
        if profile.is_demo:
            parser = OpenAPIParser(DEMO_SPEC_YAML)
            operations = parser.extract_operations()
        else:
            print(f"[ERROR] Failed to load OpenAPI spec: {e}", file=sys.stderr)
            return 2
    print(f"[*] Ingested OpenAPI spec: {len(operations)} operations normalized.")

    graph = ResourceGraph()
    graph.build_from_operations(operations)
    print(f"[*] Dependency DAG constructed: {len(graph.nodes)} nodes, {len(graph.edges)} edges.")

    # DRY RUN MODE: strictly ZERO HTTP requests sent
    if dry_run:
        print("\n[DRY RUN MODE ENABLED - ZERO REQUESTS SENT]")
        identities = {}
        for ident in profile.identities:
            identities[ident.name] = IdentityProfile(
                identity_id=ident.identity_id or ident.name,
                username=ident.username or ident.name,
                password=ident.password or "",
                role=ident.role,
                token=ident.token or f"mock_token_{ident.name}",
                headers=ident.headers or {}
            )
        owner_name = profile.owner
        attacker_name = profile.attacker
        if owner_name not in identities:
            print(f"[ERROR] Owner identity '{owner_name}' missing from profile identities", file=sys.stderr)
            return 2
        if attacker_name not in identities:
            print(f"[ERROR] Attacker identity '{attacker_name}' missing from profile identities", file=sys.stderr)
            return 2

        user_a = identities[owner_name]
        user_b = identities[attacker_name]
        print(f"[*] Dry-run identities: Owner ({user_a.username}), Attacker ({user_b.username})")

        planner = TestPlanner(graph, target_url, target_profile=profile)
        for op in operations:
            steps = planner.plan_audit_for_operation(op, user_a, user_b, enable_mutations=enable_mutations)
            if steps:
                print(f"\nPlanned sequence for {op.method} {op.path}:")
                for s in steps:
                    print(f"  - [{s.purpose}] {s.method} {s.url} (Identity: {s.identity_id})")
        print("\n[SUCCESS] Dry-run completed. All prerequisite paths validated.")
        return 0

    client = None
    if profile.is_demo:
        is_live = False
        try:
            async with httpx.AsyncClient(timeout=0.5) as check_client:
                r = await check_client.get(f"{target_url.rsplit('/target', 1)[0]}/api/health")
                if r.status_code == 200:
                    is_live = True
        except Exception:
            is_live = False

        if is_live:
            print("[*] Connected to live target server at", target_url)
            auth_reg = AuthRegistry(profile)
            try:
                identities = await auth_reg.authenticate_all()
            except Exception as e:
                print(f"[ERROR] Authentication failed: {e}", file=sys.stderr)
                return 2
        else:
            print("[*] Live server not detected on port; executing against in-process target...")
            from apiguard.main import app
            asgi_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000")
            auth_reg = AuthRegistry(profile)
            try:
                identities = await auth_reg.authenticate_all(client=asgi_client)
            except Exception as e:
                print(f"[ERROR] Authentication failed: {e}", file=sys.stderr)
                await asgi_client.aclose()
                return 2
            client = asgi_client
    else:
        # Non-demo profile: no /api/health check, no ASGI fallback
        auth_reg = AuthRegistry(profile)
        try:
            identities = await auth_reg.authenticate_all()
        except (httpx.ConnectError, httpx.ConnectTimeout) as e:
            print(f"[ERROR] Target unreachable: could not connect to {target_url} ({e})", file=sys.stderr)
            return 2
        except Exception as e:
            print(f"[ERROR] Authentication or connection error: {e}", file=sys.stderr)
            return 2

    owner_name = profile.owner
    attacker_name = profile.attacker
    if owner_name not in identities:
        print(f"[ERROR] Owner identity '{owner_name}' missing from profile identities", file=sys.stderr)
        if client:
            await client.aclose()
        return 2
    if attacker_name not in identities:
        print(f"[ERROR] Attacker identity '{attacker_name}' missing from profile identities", file=sys.stderr)
        if client:
            await client.aclose()
        return 2

    user_a = identities[owner_name]
    user_b = identities[attacker_name]
    print(f"[*] Dynamic login verified: Owner ({user_a.username}), Attacker ({user_b.username})")

    print("\n[*] Initiating Dual-Token Graph Execution...")
    if profile.is_demo:
        reset_db()
        update_target_config(defect_a=False, defect_b=True, defect_c=False, patched_mode=False)

    executor = SafeExecutor(allowed_hosts=set(profile.allowed_hosts), total_budget=profile.request_budget, enable_mutations=enable_mutations)
    scanner = GraphGuidedScanner(executor, target_url, target_profile=profile)

    t0 = asyncio.get_event_loop().time()
    try:
        findings = await scanner.run_scan(operations, user_a, user_b, enable_mutations=enable_mutations, client=client)
    except Exception as e:
        print(f"[ERROR] Scan execution failed: {e}", file=sys.stderr)
        if client:
            await client.aclose()
        return 2
    duration_ms = round((asyncio.get_event_loop().time() - t0) * 1000, 1)

    coverage = getattr(scanner, "coverage", None)
    zero_tested = (coverage is not None and len(coverage.resources_tested) == 0)

    if not zero_tested:
        print("\n" + "=" * 65)
        print(f"  AUDIT COMPLETE: {len(findings)} CONFIRMED VULNERABILITIES ({duration_ms}ms)")
        print("=" * 65)

        for f in findings:
            print(f"\n[!] FINDING: {f.id} — {f.severity}")
            print(f"    Endpoint:      {f.method} {f.endpoint}")
            print(f"    Status:        {f.status.value.upper()} (Differential Payload Match)")
            print(f"    Confidence:    {f.confidence}")
            print(f"    DAG Path:      {' -> '.join(f.graph_path)}")
            print(f"    Leaked Fields: {f.diff_fields}")
            print(f"    Repro Curl:    {f.repro_curl}")

    if client:
        await client.aclose()

    if coverage:
        for skip in coverage.skipped:
            print(f"[-] Skipped resource '{skip.resource}': {skip.reason}")
        print(f"[*] Coverage: Tested {len(coverage.resources_tested)} of {len(coverage.resources_found)} resources.")

    confirmed_findings = [f for f in findings if f.status == FindingStatus.CONFIRMED]
    if len(confirmed_findings) > 0:
        return 1

    if zero_tested:
        sys.stdout.flush()
        print("[ERROR] Nothing was tested - check base_url, credentials and spec", file=sys.stderr)
        sys.stderr.flush()
        return 2

    if coverage and len(coverage.skipped) > 0:
        print(f"[WARNING] Partial coverage: {len(coverage.skipped)} of {len(coverage.resources_found)} resources were skipped.")

    return 0

if __name__ == "__main__":
    main()

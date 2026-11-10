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
from apiguard.engine.target import load_target_profile, TargetProfile, is_admin_operation
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
        admin_name = getattr(profile, "admin", "admin")
        admin_user = identities.get(admin_name) if admin_name else None

        if admin_user:
            print(f"[*] Dry-run identities: Owner ({user_a.username}), Attacker ({user_b.username}), Admin ({admin_user.username})")
        else:
            print(f"[*] Dry-run identities: Owner ({user_a.username}), Attacker ({user_b.username})")
            if admin_name:
                print(f"[*] Admin identity '{admin_name}' not found; skipping BFLA scan.")

        bola_ops = [op for op in operations if not is_admin_operation(op, profile)]
        admin_ops = [op for op in operations if is_admin_operation(op, profile)]

        planner = TestPlanner(graph, target_url, target_profile=profile)
        for op in bola_ops:
            steps = planner.plan_audit_for_operation(op, user_a, user_b, enable_mutations=enable_mutations)
            if steps:
                print(f"\nPlanned sequence for {op.method} {op.path}:")
                for s in steps:
                    print(f"  - [{s.purpose}] {s.method} {s.url} (Identity: {s.identity_id})")

        if admin_user and admin_ops:
            print("\n" + "=" * 65)
            print("  BFLA PRIVILEGE ESCALATION CHECKS (Admin Operations)")
            print("=" * 65)
            for op in admin_ops:
                url = f"{target_url}{op.path}"
                print(f"\nPlanned BFLA sequence for {op.method} {op.path}:")
                print(f"  - [control_admin] {op.method} {url} (Identity: {admin_user.identity_id})")
                print(f"  - [probe_adversary] {op.method} {url} (Identity: {user_b.identity_id})")

        producer_ops = [op for op in operations if op.method == "POST" and not op.path_params and op.path.lower() not in {"/auth/login", "/auth/refresh"}]
        mutation_ops = [op for op in operations if op.method in {"PATCH", "PUT"} and op.path_params]
        if producer_ops or mutation_ops:
            print("\n" + "=" * 65)
            print("  BOPLA PROPERTY INJECTION CHECKS (Mass Assignment)")
            print("=" * 65)
            for op in producer_ops:
                url = f"{target_url}{op.path}"
                print(f"\nPlanned BOPLA Mass Assignment for {op.method} {op.path}:")
                print(f"  - [probe_mass_assignment] {op.method} {url} (Identity: {user_a.identity_id}) [Fields: role, is_admin, owner_id]")
            for op in mutation_ops:
                url = f"{target_url}{op.path}"
                if enable_mutations:
                    print(f"\nPlanned BOPLA Mass Assignment for {op.method} {op.path}:")
                    print(f"  - [probe_mass_assignment] {op.method} {url} (Identity: {user_a.identity_id}) [Fields: role, is_admin, owner_id]")
                else:
                    print(f"\nPlanned BOPLA Mass Assignment for {op.method} {op.path}: [MUTATION GATE: skipped without --mutations]")

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
    admin_name = getattr(profile, "admin", "admin")
    admin_user = identities.get(admin_name) if admin_name else None

    if admin_user:
        print(f"[*] Dynamic login verified: Owner ({user_a.username}), Attacker ({user_b.username}), Admin ({admin_user.username})")
    else:
        print(f"[*] Dynamic login verified: Owner ({user_a.username}), Attacker ({user_b.username})")
        if admin_name:
            print(f"[*] Admin identity '{admin_name}' not found; skipping BFLA scan.")

    print("\n[*] Initiating Dual-Token Graph Execution...")
    if profile.is_demo:
        reset_db()
        update_target_config(defect_a=False, defect_b=True, defect_c=False, defect_bfla=False, patched_mode=False)

    executor = SafeExecutor(allowed_hosts=set(profile.allowed_hosts), total_budget=profile.request_budget, enable_mutations=enable_mutations)
    scanner = GraphGuidedScanner(executor, target_url, target_profile=profile)

    t0 = asyncio.get_event_loop().time()
    try:
        findings = await scanner.run_scan(operations, user_a, user_b, admin_user=admin_user, enable_mutations=enable_mutations, client=client)
    except Exception as e:
        print(f"[ERROR] Scan execution failed: {e}", file=sys.stderr)
        if client:
            await client.aclose()
        return 2
    duration_ms = round((asyncio.get_event_loop().time() - t0) * 1000, 1)

    coverage = getattr(scanner, "coverage", None)
    zero_tested = (
        coverage is not None
        and len(coverage.resources_tested) == 0
        and len(coverage.admin_operations_tested) == 0
        and len(getattr(coverage, "bopla_operations_tested", [])) == 0
    )

    confirmed_findings = [f for f in findings if f.status == FindingStatus.CONFIRMED]

    if not zero_tested:
        print("\n" + "=" * 65)
        print(f"  AUDIT COMPLETE: {len(confirmed_findings)} CONFIRMED VULNERABILITIES ({duration_ms}ms)")
        print("=" * 65)

        bola_findings = [f for f in findings if getattr(f, "category", "BOLA") == "BOLA"]
        bfla_findings = [f for f in findings if getattr(f, "category", "BOLA") == "BFLA"]
        bopla_findings = [f for f in findings if getattr(f, "category", "BOLA") == "BOPLA"]

        for f in bola_findings:
            if f.status == FindingStatus.POTENTIAL:
                print(f"\n[?] NEEDS REVIEW: {f.id} — {f.severity}")
                print(f"    Endpoint:      {f.method} {f.endpoint}")
                print(f"    Status:        POTENTIAL (attacker got 2xx but no owner data leaked)")
                print(f"    Confidence:    {f.confidence}")
                print(f"    DAG Path:      {' -> '.join(f.graph_path)}")
                print(f"    Leaked Fields: {f.diff_fields}")
                print(f"    Repro Curl:    {f.repro_curl}")
            else:
                print(f"\n[!] BOLA FINDING: {f.id} — {f.severity}")
                print(f"    Endpoint:      {f.method} {f.endpoint}")
                print(f"    Status:        {f.status.value.upper()} (Differential Payload Match)")
                print(f"    Confidence:    {f.confidence}")
                print(f"    DAG Path:      {' -> '.join(f.graph_path)}")
                print(f"    Leaked Fields: {f.diff_fields}")
                print(f"    Repro Curl:    {f.repro_curl}")

        for f in bfla_findings:
            if f.status == FindingStatus.POTENTIAL:
                print(f"\n[?] NEEDS REVIEW: {f.id} — {f.severity}")
                print(f"    Endpoint:      {f.method} {f.endpoint}")
                print(f"    Status:        POTENTIAL (attacker got 2xx but the response differs from the admin's)")
                print(f"    Confidence:    {f.confidence}")
                print(f"    Repro Curl:    {f.repro_curl}")
            else:
                print(f"\n[!] BFLA FINDING: {f.id} — {f.severity}")
                print(f"    Endpoint:      {f.method} {f.endpoint}")
                print(f"    Status:        {f.status.value.upper()} (Privilege Escalation: Attacker accessed admin function)")
                print(f"    Confidence:    {f.confidence}")
                print(f"    Repro Curl:    {f.repro_curl}")

        for f in bopla_findings:
            if f.status == FindingStatus.POTENTIAL:
                print(f"\n[?] NEEDS REVIEW: {f.id} — {f.severity}")
                print(f"    Endpoint:      {f.method} {f.endpoint}")
                print(f"    Status:        POTENTIAL (injected fields echoed but not persisted in read-back)")
                print(f"    Confidence:    {f.confidence}")
                print(f"    Leaked Fields: {f.diff_fields}")
                print(f"    Repro Curl:    {f.repro_curl}")
            else:
                print(f"\n[!] BOPLA FINDING: {f.id} — {f.severity}")
                print(f"    Endpoint:      {f.method} {f.endpoint}")
                desc = "Property-Level Violation"
                print(f"    Status:        {f.status.value.upper()} ({desc})")
                print(f"    Confidence:    {f.confidence}")
                print(f"    Leaked Fields: {f.diff_fields}")
                print(f"    Repro Curl:    {f.repro_curl}")

    if client:
        await client.aclose()

    if coverage:
        for skip in coverage.skipped:
            print(f"[-] Skipped resource '{skip.resource}': {skip.reason}")
        print(f"[*] Coverage: Tested {len(coverage.resources_tested)} of {len(coverage.resources_found)} resources.")
        if coverage.admin_operations_found:
            print(f"[*] BFLA Coverage: Tested {len(coverage.admin_operations_tested)} of {len(coverage.admin_operations_found)} admin operations.")
        if coverage.bopla_operations_found:
            print(f"[*] BOPLA Coverage: Tested {len(coverage.bopla_operations_tested)} of {len(coverage.bopla_operations_found)} BOPLA checks.")

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

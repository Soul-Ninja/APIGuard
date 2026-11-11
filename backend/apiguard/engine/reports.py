import hashlib
import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from apiguard.engine.models import Finding, FindingStatus
from apiguard.engine.target import TargetProfile, resolve_file_path

RULES_METADATA: Dict[str, Dict[str, Any]] = {
    "APIGUARD-BOLA": {
        "name": "BrokenObjectLevelAuthorization",
        "shortDescription": "Broken Object Level Authorization (BOLA/IDOR)",
        "fullDescription": "Endpoint allows access to another tenant's object without proper authorization check.",
        "owasp": "API1:2023",
        "severity": "HIGH",
        "security-severity": "7.5",
        "helpUri": "https://github.com/Soul-Ninja/APIGuard#bola"
    },
    "APIGUARD-BFLA": {
        "name": "BrokenFunctionLevelAuthorization",
        "shortDescription": "Broken Function Level Authorization (BFLA)",
        "fullDescription": "Administrative function is callable by unauthorized non-admin identities.",
        "owasp": "API5:2023",
        "severity": "HIGH",
        "security-severity": "7.5",
        "helpUri": "https://github.com/Soul-Ninja/APIGuard#bfla"
    },
    "APIGUARD-BOPLA-MASS-ASSIGNMENT": {
        "name": "BOPLAMassAssignment",
        "shortDescription": "Broken Object Property Level Authorization - Mass Assignment",
        "fullDescription": "Endpoint accepts and persists unauthorized object properties (e.g. role, admin flags).",
        "owasp": "API3:2023",
        "severity": "HIGH",
        "security-severity": "7.5",
        "helpUri": "https://github.com/Soul-Ninja/APIGuard#bopla"
    },
    "APIGUARD-BOPLA-EXPOSURE": {
        "name": "BOPLAExcessiveDataExposure",
        "shortDescription": "Broken Object Property Level Authorization - Excessive Data Exposure",
        "fullDescription": "Response payload discloses sensitive fields not declared in the OpenAPI specification.",
        "owasp": "API3:2023",
        "severity": "MEDIUM",
        "security-severity": "5.0",
        "helpUri": "https://github.com/Soul-Ninja/APIGuard#bopla"
    },
    "APIGUARD-AUTH": {
        "name": "BrokenAuthentication",
        "shortDescription": "Broken Authentication",
        "fullDescription": "Protected endpoint accepts requests with missing, forged, altered, or expired tokens.",
        "owasp": "API2:2023",
        "severity": "HIGH",
        "security-severity": "7.5",
        "helpUri": "https://github.com/Soul-Ninja/APIGuard#auth"
    },
    "APIGUARD-MISCONFIG-CORS": {
        "name": "MisconfigCORSWildcardCredentials",
        "shortDescription": "CORS Wildcard Origin with Credentials Allowed",
        "fullDescription": "Access-Control-Allow-Origin is configured as wildcard combined with Access-Control-Allow-Credentials.",
        "owasp": "API8:2023",
        "severity": "MEDIUM",
        "security-severity": "5.0",
        "helpUri": "https://github.com/Soul-Ninja/APIGuard#misconfig"
    },
    "APIGUARD-MISCONFIG-VERBOSE-ERROR": {
        "name": "MisconfigVerboseError",
        "shortDescription": "Verbose Error / Stack Trace Disclosure",
        "fullDescription": "Response body discloses server stack trace or internal database error messages.",
        "owasp": "API8:2023",
        "severity": "MEDIUM",
        "security-severity": "5.0",
        "helpUri": "https://github.com/Soul-Ninja/APIGuard#misconfig"
    },
    "APIGUARD-MISCONFIG-VERSION": {
        "name": "MisconfigVersionDisclosure",
        "shortDescription": "Server or Framework Version Disclosure",
        "fullDescription": "Server or X-Powered-By HTTP headers disclose exact software versions.",
        "owasp": "API8:2023",
        "severity": "LOW",
        "security-severity": "3.0",
        "helpUri": "https://github.com/Soul-Ninja/APIGuard#misconfig"
    },
    "APIGUARD-MISCONFIG-NOSNIFF": {
        "name": "MisconfigMissingNosniff",
        "shortDescription": "Missing X-Content-Type-Options Header",
        "fullDescription": "JSON response is served without X-Content-Type-Options: nosniff header.",
        "owasp": "API8:2023",
        "severity": "LOW",
        "security-severity": "3.0",
        "helpUri": "https://github.com/Soul-Ninja/APIGuard#misconfig"
    },
    "APIGUARD-MISCONFIG-HSTS": {
        "name": "MisconfigMissingHSTS",
        "shortDescription": "Missing Strict-Transport-Security Header",
        "fullDescription": "HTTPS API response is served without Strict-Transport-Security (HSTS) header.",
        "owasp": "API8:2023",
        "severity": "LOW",
        "security-severity": "3.0",
        "helpUri": "https://github.com/Soul-Ninja/APIGuard#misconfig"
    },
    "APIGUARD-MISCONFIG-CACHE": {
        "name": "MisconfigInsecureCacheControl",
        "shortDescription": "Insecure Cache-Control on Sensitive Data",
        "fullDescription": "Authenticated response carrying sensitive user data lacks no-store or private Cache-Control directive.",
        "owasp": "API8:2023",
        "severity": "LOW",
        "security-severity": "3.0",
        "helpUri": "https://github.com/Soul-Ninja/APIGuard#misconfig"
    },
    "APIGUARD-INVENTORY-DEPRECATED": {
        "name": "InventoryDeprecatedEndpointLive",
        "shortDescription": "Deprecated Endpoint Still Live",
        "fullDescription": "Endpoint marked deprecated in OpenAPI schema continues to accept and process requests.",
        "owasp": "API9:2023",
        "severity": "LOW",
        "security-severity": "3.0",
        "helpUri": "https://github.com/Soul-Ninja/APIGuard#inventory"
    },
    "APIGUARD-INVENTORY-UNDOCUMENTED": {
        "name": "InventoryUndocumentedStatusCode",
        "shortDescription": "Undocumented Response Status Code",
        "fullDescription": "Endpoint returned an HTTP status code not declared in the OpenAPI specification.",
        "owasp": "API9:2023",
        "severity": "INFO",
        "security-severity": "1.0",
        "helpUri": "https://github.com/Soul-Ninja/APIGuard#inventory"
    }
}

SEVERITY_SECURITY_SCORE: Dict[str, str] = {
    "CRITICAL": "9.5",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "3.0",
    "INFO": "1.0"
}


def get_version() -> str:
    """Reads installed package version from package metadata, falling back to 'dev'."""
    try:
        import importlib.metadata
        for pkg_name in ("apiguard-cli", "apiguard"):
            try:
                return importlib.metadata.version(pkg_name)
            except importlib.metadata.PackageNotFoundError:
                pass
    except Exception:
        pass
    return "dev"


def map_finding_to_rule_id(finding: Finding) -> str:
    cat = (getattr(finding, "category", "") or "BOLA").upper()
    if cat == "BOLA":
        return "APIGUARD-BOLA"
    elif cat == "BFLA":
        return "APIGUARD-BFLA"
    elif cat == "BOPLA":
        res_type = (getattr(finding, "resource_type", "") or "").lower()
        hyp_res = (finding.hypothesis.rule.resource_type if finding.hypothesis and finding.hypothesis.rule else "").lower()
        ep = (getattr(finding, "endpoint", "") or "").lower()
        if "mass" in res_type or "mass" in hyp_res or "mass" in ep:
            return "APIGUARD-BOPLA-MASS-ASSIGNMENT"
        return "APIGUARD-BOPLA-EXPOSURE"
    elif cat == "AUTH":
        return "APIGUARD-AUTH"
    elif cat == "MISCONFIG":
        fid = (getattr(finding, "id", "") or "").lower()
        ep = (getattr(finding, "endpoint", "") or "").lower()
        res_type = (getattr(finding, "resource_type", "") or "").lower()
        if "cors" in ep or "cors" in res_type or "cors" in fid:
            return "APIGUARD-MISCONFIG-CORS"
        elif "verbose" in fid or "verbose" in res_type or "stack trace" in str(finding.probe_evidence).lower():
            return "APIGUARD-MISCONFIG-VERBOSE-ERROR"
        elif "version" in ep or "version" in res_type or "version" in fid:
            return "APIGUARD-MISCONFIG-VERSION"
        elif "nosniff" in fid or "x-content-type-options" in ep or "nosniff" in res_type:
            return "APIGUARD-MISCONFIG-NOSNIFF"
        elif "hsts" in fid or "strict-transport-security" in ep or "hsts" in res_type:
            return "APIGUARD-MISCONFIG-HSTS"
        elif "cache" in ep or "cache" in res_type or "cache" in fid:
            return "APIGUARD-MISCONFIG-CACHE"
        return "APIGUARD-MISCONFIG-CORS"
    elif cat == "INVENTORY":
        fid = (getattr(finding, "id", "") or "").lower()
        ep = (getattr(finding, "endpoint", "") or "").lower()
        res_type = (getattr(finding, "resource_type", "") or "").lower()
        if "deprecated" in fid or "deprecated" in ep or "deprecated" in res_type:
            return "APIGUARD-INVENTORY-DEPRECATED"
        return "APIGUARD-INVENTORY-UNDOCUMENTED"
    return "APIGUARD-BOLA"


def find_spec_line(spec_content: str, endpoint: str) -> int:
    """Finds the 1-indexed line where endpoint path key appears in spec, or 1 if not found."""
    if not endpoint or not endpoint.startswith("/"):
        return 1
    lines = spec_content.splitlines()
    pattern = re.compile(r'^\s*[\'"]?' + re.escape(endpoint) + r'[\'"]?\s*:\s*(?:#.*)?$')
    for idx, line in enumerate(lines):
        if pattern.match(line):
            return idx + 1
    # Fallback to simple substring match with colon
    sub = f"{endpoint}:"
    for idx, line in enumerate(lines):
        if sub in line:
            return idx + 1
    return 1


def sanitize_secrets(text: str, profile: Optional[TargetProfile]) -> str:
    """Ensures no real identity tokens, passwords, or expired tokens appear in report output."""
    if not profile or not profile.identities:
        return text
    result = text
    for ident in profile.identities:
        for val in (ident.token, ident.password, ident.expired_token):
            if val and len(val) >= 4 and val in result:
                result = result.replace(val, "<REDACTED>")
    return result


def generate_json_report(
    findings: List[Finding],
    profile: TargetProfile,
    coverage: Optional[Any] = None
) -> Dict[str, Any]:
    counts_by_cat: Dict[str, int] = {}
    counts_by_status: Dict[str, int] = {}
    counts_by_sev: Dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
    }

    for f in findings:
        cat = getattr(f, "category", "BOLA") or "BOLA"
        counts_by_cat[cat] = counts_by_cat.get(cat, 0) + 1
        st = f.status.value if hasattr(f.status, "value") else str(f.status)
        counts_by_status[st] = counts_by_status.get(st, 0) + 1
        sev = f.severity.upper() if f.severity else "INFO"
        counts_by_sev[sev] = counts_by_sev.get(sev, 0) + 1

    cov_dict: Dict[str, Any] = {}
    if coverage:
        cov_dict = {
            "resources_found": coverage.resources_found,
            "resources_tested": coverage.resources_tested,
            "skipped": [{"resource": s.resource, "reason": s.reason} for s in coverage.skipped],
            "admin_operations_found": coverage.admin_operations_found,
            "admin_operations_tested": coverage.admin_operations_tested,
            "bopla_operations_found": coverage.bopla_operations_found,
            "bopla_operations_tested": coverage.bopla_operations_tested,
            "auth_operations_found": getattr(coverage, "auth_operations_found", []),
            "auth_operations_tested": getattr(coverage, "auth_operations_tested", [])
        }

    findings_dump = []
    for f in findings:
        if hasattr(f, "model_dump"):
            findings_dump.append(f.model_dump(mode="json"))
        elif hasattr(f, "dict"):
            findings_dump.append(f.dict())
        else:
            findings_dump.append(str(f))

    return {
        "version": get_version(),
        "base_url": profile.base_url,
        "summary": {
            "total_findings": len(findings),
            "confirmed": sum(1 for f in findings if f.status == FindingStatus.CONFIRMED),
            "potential": sum(1 for f in findings if f.status == FindingStatus.POTENTIAL),
            "counts_by_category": counts_by_cat,
            "counts_by_status": counts_by_status,
            "counts_by_severity": counts_by_sev
        },
        "coverage": cov_dict,
        "findings": findings_dump
    }


def generate_sarif(
    findings: List[Finding],
    profile: TargetProfile
) -> Dict[str, Any]:
    tool_version = get_version()
    spec_path_str = getattr(profile, "spec_path", "demo_spec.yaml") or "demo_spec.yaml"
    resolved_spec = resolve_file_path(spec_path_str)
    try:
        rel_spec_uri = resolved_spec.relative_to(Path.cwd()).as_posix()
    except ValueError:
        rel_spec_uri = resolved_spec.as_posix()

    spec_content = ""
    if resolved_spec.is_file():
        try:
            spec_content = resolved_spec.read_text(encoding="utf-8")
        except Exception:
            spec_content = ""

    rules_used: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for f in findings:
        rule_id = map_finding_to_rule_id(f)
        meta = RULES_METADATA.get(rule_id, {
            "name": rule_id,
            "shortDescription": rule_id,
            "fullDescription": rule_id,
            "owasp": "API1:2023",
            "severity": f.severity or "HIGH",
            "security-severity": "7.5",
            "helpUri": "https://github.com/Soul-Ninja/APIGuard"
        })

        if rule_id not in rules_used:
            rules_used[rule_id] = {
                "id": rule_id,
                "name": meta["name"],
                "shortDescription": {"text": meta["shortDescription"]},
                "fullDescription": {"text": meta["fullDescription"]},
                "helpUri": meta["helpUri"],
                "properties": {
                    "tags": ["security", meta["owasp"]],
                    "security-severity": meta["security-severity"]
                }
            }

        # Level mapping: POTENTIAL is always "note"
        if f.status == FindingStatus.POTENTIAL:
            level = "note"
        else:
            sev = (f.severity or "INFO").upper()
            if sev in ("CRITICAL", "HIGH"):
                level = "error"
            elif sev == "MEDIUM":
                level = "warning"
            else:
                level = "note"

        # Message text
        msg_lines = []
        if f.status == FindingStatus.POTENTIAL:
            msg_lines.append(f"Needs review: Potential {f.category} issue detected on {f.method} {f.endpoint}.")
        else:
            msg_lines.append(f"Confirmed {f.category} vulnerability detected on {f.method} {f.endpoint}.")

        if f.probe_evidence:
            ev = f.probe_evidence.get("evidence") if isinstance(f.probe_evidence, dict) else str(f.probe_evidence)
            if ev:
                msg_lines.append(f"Evidence: {ev}")
        if f.diff_fields:
            msg_lines.append(f"Details: {', '.join(f.diff_fields)}")
        if f.repro_curl:
            msg_lines.append(f"Reproduction: {f.repro_curl}")
        message_text = "\n".join(msg_lines)

        # Start line in spec
        start_line = find_spec_line(spec_content, f.endpoint)

        # Deterministic fingerprint across runs: sha256(category|method|endpoint|rule_id)
        cat = getattr(f, "category", "BOLA") or "BOLA"
        fingerprint_raw = f"{cat}|{f.method}|{f.endpoint}|{rule_id}"
        fingerprint = hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()

        sec_score = SEVERITY_SECURITY_SCORE.get((f.severity or "INFO").upper(), "1.0")

        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": rel_spec_uri},
                        "region": {"startLine": start_line}
                    },
                    "logicalLocations": [
                        {
                            "name": f"{f.method} {f.endpoint}",
                            "kind": "endpoint"
                        }
                    ]
                }
            ],
            "properties": {
                "security-severity": sec_score
            },
            "partialFingerprints": {
                "apiguardFindingKey/v1": fingerprint
            }
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "APIGuard",
                        "version": tool_version,
                        "informationUri": "https://github.com/Soul-Ninja/APIGuard",
                        "rules": list(rules_used.values())
                    }
                },
                "results": sarif_results
            }
        ]
    }


def generate_markdown_report(
    findings: List[Finding],
    profile: TargetProfile,
    coverage: Optional[Any] = None
) -> str:
    confirmed_active = [
        f for f in findings
        if f.status == FindingStatus.CONFIRMED and getattr(f, "category", "BOLA") in ("BOLA", "BFLA", "BOPLA", "AUTH")
    ]
    confirmed_passive = [
        f for f in findings
        if f.status == FindingStatus.CONFIRMED and getattr(f, "category", "BOLA") in ("MISCONFIG", "INVENTORY")
    ]
    potential_findings = [
        f for f in findings
        if f.status == FindingStatus.POTENTIAL
    ]

    # One-line verdict
    if confirmed_active:
        verdict = f"## ❌ APIGuard Security Scan: {len(confirmed_active)} Confirmed Vulnerabilit{'y' if len(confirmed_active) == 1 else 'ies'} Found"
    elif confirmed_passive:
        verdict = f"## ⚠️ APIGuard Security Scan: {len(confirmed_passive)} Passive Misconfiguration / Hygiene Finding{'s' if len(confirmed_passive) != 1 else ''}"
    elif potential_findings:
        verdict = f"## ⚠️ APIGuard Security Scan: {len(potential_findings)} Finding{'s' if len(potential_findings) != 1 else ''} Need Review"
    else:
        verdict = "## ✅ APIGuard Security Scan: Passed — 0 Confirmed Vulnerabilities"

    # Category counts table
    categories = ["BOLA", "BFLA", "BOPLA", "AUTH", "MISCONFIG", "INVENTORY"]
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    matrix: Dict[str, Dict[str, int]] = {c: {s: 0 for s in severities} for c in categories}

    for f in findings:
        cat = (getattr(f, "category", "BOLA") or "BOLA").upper()
        if cat not in matrix:
            matrix[cat] = {s: 0 for s in severities}
        sev = (f.severity or "INFO").upper()
        if sev not in matrix[cat]:
            matrix[cat][sev] = 0
        matrix[cat][sev] += 1

    table_lines = [
        "| Category | Critical | High | Medium | Low | Info | Total |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |"
    ]
    tot_crit = sum(matrix[c]["CRITICAL"] for c in matrix)
    tot_high = sum(matrix[c]["HIGH"] for c in matrix)
    tot_med = sum(matrix[c]["MEDIUM"] for c in matrix)
    tot_low = sum(matrix[c]["LOW"] for c in matrix)
    tot_info = sum(matrix[c]["INFO"] for c in matrix)
    tot_all = tot_crit + tot_high + tot_med + tot_low + tot_info

    for c in categories:
        row_tot = sum(matrix[c].values())
        if row_tot > 0 or c in ("BOLA", "BFLA", "BOPLA", "AUTH"):
            table_lines.append(
                f"| `{c}` | {matrix[c]['CRITICAL']} | {matrix[c]['HIGH']} | {matrix[c]['MEDIUM']} | {matrix[c]['LOW']} | {matrix[c]['INFO']} | **{row_tot}** |"
            )
    table_lines.append(
        f"| **Total** | **{tot_crit}** | **{tot_high}** | **{tot_med}** | **{tot_low}** | **{tot_info}** | **{tot_all}** |"
    )

    # Coverage line
    cov_line = "**Coverage:** No coverage data available."
    if coverage:
        tested_res = len(coverage.resources_tested)
        found_res = len(coverage.resources_found)
        skip_cnt = len(coverage.skipped)
        cov_line = f"**Coverage:** Tested {tested_res} of {found_res} resources ({skip_cnt} skip reason{'s' if skip_cnt != 1 else ''})."
        parts = []
        if coverage.admin_operations_found:
            parts.append(f"{len(coverage.admin_operations_tested)}/{len(coverage.admin_operations_found)} admin ops")
        if coverage.bopla_operations_found:
            parts.append(f"{len(coverage.bopla_operations_tested)}/{len(coverage.bopla_operations_found)} BOPLA checks")
        if getattr(coverage, "auth_operations_found", None):
            parts.append(f"{len(coverage.auth_operations_tested)}/{len(coverage.auth_operations_found)} auth checks")
        if parts:
            cov_line += f" Additional checks: {', '.join(parts)}."

    # Grouped findings builder
    def format_finding_item(f: Finding) -> str:
        lines = [f"- **{f.method} {f.endpoint}** — `{f.severity}` ({getattr(f, 'category', 'BOLA')})"]
        if f.probe_evidence:
            ev = f.probe_evidence.get("evidence") if isinstance(f.probe_evidence, dict) else str(f.probe_evidence)
            if ev:
                lines.append(f"  - *Evidence:* {ev}")
        if f.diff_fields:
            if len(f.diff_fields) <= 5:
                lines.append(f"  - *Details:* {', '.join(f.diff_fields)}")
            else:
                lines.append(f"  - *Details:* {', '.join(f.diff_fields[:5])} (+{len(f.diff_fields) - 5} more)")
        if f.repro_curl:
            lines.append(f"  - *Repro:*\n    ```bash\n    {f.repro_curl}\n    ```")
        return "\n".join(lines)

    header = "<!-- apiguard-report -->\n\n" + verdict + "\n\n" + "\n".join(table_lines) + "\n\n" + cov_line + "\n"

    sections: List[Tuple[str, List[Finding]]] = [
        ("### 🔴 Confirmed Vulnerabilities", confirmed_active),
        ("### 🟡 Needs Review", potential_findings),
        ("### 🔵 Passive Findings", confirmed_passive)
    ]

    rendered_items: List[str] = []
    for sec_title, group in sections:
        if group:
            rendered_items.append(f"\n{sec_title}\n")
            for item in group:
                rendered_items.append(format_finding_item(item))

    # Assemble and apply 60,000 character hard cap
    full_doc = header + "\n" + "\n\n".join(rendered_items)
    if len(full_doc) <= 60000:
        return full_doc

    # If exceeding 60,000 chars, truncate items from bottom
    curr_items = list(rendered_items)
    dropped = 0
    while curr_items and len(header + "\n" + "\n\n".join(curr_items) + f"\n\n*... {dropped} more findings, see the SARIF/JSON report.*") > 60000:
        curr_items.pop()
        dropped += 1

    return header + "\n" + "\n\n".join(curr_items) + f"\n\n*... {dropped} more findings, see the SARIF/JSON report.*"


def write_reports(
    findings: List[Finding],
    profile: TargetProfile,
    coverage: Optional[Any] = None,
    json_path: Optional[str] = None,
    sarif_path: Optional[str] = None,
    markdown_path: Optional[str] = None
) -> None:
    if json_path:
        data = generate_json_report(findings, profile, coverage)
        content = json.dumps(data, indent=2)
        content = sanitize_secrets(content, profile)
        p = Path(json_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    if sarif_path:
        data = generate_sarif(findings, profile)
        content = json.dumps(data, indent=2)
        content = sanitize_secrets(content, profile)
        p = Path(sarif_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    if markdown_path:
        content = generate_markdown_report(findings, profile, coverage)
        content = sanitize_secrets(content, profile)
        p = Path(markdown_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

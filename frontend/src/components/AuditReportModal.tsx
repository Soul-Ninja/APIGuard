import React, { useState, useMemo } from 'react';
import { 
  X, 
  FileText, 
  Download, 
  Copy, 
  Check, 
  Printer, 
  ShieldAlert, 
  ShieldCheck, 
  GitBranch,
  Terminal
} from 'lucide-react';
import type { Finding } from '../types';

interface AuditReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  /** Render as a normal page section instead of a full-screen overlay */
  inline?: boolean;
  findings: Finding[];
  operationCount: number;
  edgeCount: number;
  targetUrl?: string;
  isTargetPatched?: boolean;
}

// Finding fields originate from the imported spec and target responses, so treat them as untrusted.
const escapeHtml = (value: unknown): string =>
  String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

// Keeps a value safe inside a single-line Markdown inline-code span.
const mdInline = (value: unknown): string =>
  String(value ?? '').replace(/[`\r\n]/g, ' ');

// Keeps a value from closing a fenced code block early.
const mdFenced = (value: unknown): string =>
  String(value ?? '').replace(/```/g, "'''");

const toIdentifier = (value: unknown): string =>
  String(value ?? 'resource').replace(/[^a-zA-Z0-9_]/g, '_').toLowerCase();

export const AuditReportModal: React.FC<AuditReportModalProps> = ({
  isOpen,
  onClose,
  inline = false,
  findings,
  operationCount,
  edgeCount,
  targetUrl = 'https://api.target.internal/v1',
  isTargetPatched = false,
}) => {
  const [activeTab, setActiveTab] = useState<'preview' | 'markdown'>('preview');
  const [copied, setCopied] = useState(false);

  const reportDate = useMemo(() => new Date().toLocaleString(), []);
  const reportTimestamp = useMemo(() => new Date().toISOString().replace(/[:.]/g, '-'), []);

  // Generate Markdown representation
  const markdownContent = useMemo(() => {
    const isClean = findings.length === 0;
    const lines: string[] = [];

    lines.push('# 🛡️ APIGuard Security Assessment & BOLA Audit Report\n');
    lines.push(`**Generated At:** ${reportDate}`);
    lines.push(`**Target Host:** \`${mdInline(targetUrl)}\``);
    lines.push(`**Testing Methodology:** Resource Graph-Guided Multi-Identity Differential Testing`);
    lines.push(`**Vulnerability Class:** OWASP API Security Top 10 — API1:2023 (Broken Object Level Authorization / BOLA)\n`);
    lines.push('---\n');

    lines.push('## 📊 Executive Summary\n');
    lines.push(`| Metric | Value |`);
    lines.push(`| :--- | :--- |`);
    lines.push(`| **Assessment Status** | ${isClean ? '✅ NO CONFIRMED LEAKS on the routes tested' : '🚨 VULNERABLE (Confirmed BOLA Detected)'} |`);
    lines.push(`| **Target State** | ${isTargetPatched ? 'Patched build (reference fix applied)' : 'Unpatched build'} |`);
    lines.push(`| **Operations Analyzed** | ${operationCount} operations |`);
    lines.push(`| **Dependency Edges Mapped** | ${edgeCount} graph relationships |`);
    lines.push(`| **Identities Probed** | Multi-Identity Differential (User A: Owner vs User B: Unauthorized Attacker) |`);
    lines.push(`| **Confirmed BOLA Vulnerabilities** | **${findings.length}** |`);
    lines.push(`| **Verification Method** | Response differential: a leak is confirmed only when the owner's private values appear in the attacker's response |\n`);

    if (isClean) {
      lines.push('### ✅ Security Verdict\n');
      lines.push('No confirmed object-level authorization leaks were found on the routes tested in this run. This is not proof that untested routes are secure.\n');
    } else {
      lines.push('### 🚨 Vulnerability Summary\n');
      lines.push('The following endpoints were confirmed to return sensitive victim data when probed by an unauthorized attacker identity:\n');

      findings.forEach((f, idx) => {
        const resId = toIdentifier(f.resource_type);
        lines.push(`### Finding #${idx + 1}: BOLA on \`${mdInline(f.method)} ${mdInline(f.endpoint)}\``);
        lines.push(`- **Severity:** **${mdInline(f.severity)}** `);
        lines.push(`- **Resource Type:** \`${mdInline(f.resource_type)}\``);
        lines.push(`- **Victim Identity (Owner):** \`${mdInline(f.identities.owner)}\``);
        lines.push(`- **Attacker Identity (Probe):** \`${mdInline(f.identities.probe)}\``);
        lines.push(`- **Leaked Tenant Attributes:** \`${f.diff_fields.length > 0 ? f.diff_fields.map(mdInline).join('`, `') : 'Direct Access to Private Resource'}\``);
        lines.push(`- **Propagation Hypothesis:** ${mdInline(f.hypothesis.rule.rule_type)} on \`${mdInline(f.hypothesis.operation_id)}\` (Confidence: ${(f.hypothesis.confidence * 100).toFixed(0)}%)`);
        lines.push(`- **Graph Dependency Path:** \`${f.graph_path.map(mdInline).join(' ➔ ')}\`\n`);

        lines.push('**Reproduction cURL:**');
        lines.push('```bash');
        lines.push(mdFenced(f.repro_curl));
        lines.push('```\n');

        lines.push('**Surgical Remediation Recommendation:**');
        lines.push('Implement explicit object-level tenant validation in the route handler:');
        lines.push('```python');
        lines.push('# FastAPI Dependency Enforcement');
        lines.push(`async def verify_${resId}_owner(${resId}_id: str, current_user: User = Depends(get_current_user)):`);
        lines.push(`    item = await db.get_${resId}(${resId}_id)`);
        lines.push(`    if not item or item.owner_id != current_user.id:`);
        lines.push(`        raise HTTPException(status_code=403, detail="Access forbidden: Insufficient object permissions")`);
        lines.push('    return item');
        lines.push('```\n');
      });
    }

    lines.push('---\n');
    lines.push('## 🔬 Verification Methodology & Integrity Guarantee');
    lines.push('- **Deterministic Differential Verification:** Every finding is validated by comparing the baseline response returned to the genuine resource owner with the response returned to the unauthorized identity.');
    lines.push('- **Decoy-aware:** A `200 OK` with an empty body, or with none of the owner\'s private values, is not reported as a confirmed leak.');
    lines.push('- **Safe by Default:** Execution strictly honors request budgets and loopback host restrictions.\n');

    lines.push('---\n');
    lines.push('*Report automatically generated by APIGuard: API Authorization Scanner.*');

    return lines.join('\n');
  }, [findings, operationCount, edgeCount, targetUrl, isTargetPatched, reportDate]);

  // Generate self-contained printable HTML
  const htmlContent = useMemo(() => {
    const isClean = findings.length === 0;
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>APIGuard Security Assessment Report - ${reportDate}</title>
  <style>
    :root {
      --bg: #fffcf1;
      --card-bg: #fffef8;
      --border: #d9d2ae;
      --text: #181a14;
      --text-muted: #4b5238;
      --accent: #5d7a14;
      --danger: #b3342b;
      --warning: #a97508;
    }
    @media print {
      body { background: #ffffff !important; color: #0f172a !important; font-size: 11pt; }
      .no-print { display: none !important; }
      .card { border: 1px solid #cbd5e1 !important; background: #f8fafc !important; }
      pre, code { background: #f1f5f9 !important; color: #0f172a !important; border: 1px solid #e2e8f0 !important; }
      .badge-danger { background: #fee2e2 !important; color: #991b1b !important; }
      .badge-success { background: #dcfce7 !important; color: #166534 !important; }
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, monospace;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      margin: 0;
      padding: 40px;
    }
    .container { max-width: 900px; margin: 0 auto; }
    .header { border-bottom: 2px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; }
    .brand { font-size: 24px; font-weight: bold; color: #181a14; }
    .brand span { text-shadow: 2px 2px 0 #d8e820; }
    .brand span { color: var(--accent); }
    .title { font-size: 20px; font-weight: bold; margin-top: 10px; }
    .meta { color: var(--text-muted); font-size: 13px; margin-top: 6px; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; }
    .badge-danger { background: rgba(179, 52, 43, 0.12); color: var(--danger); border: 1px solid var(--danger); }
    .badge-success { background: rgba(93, 122, 20, 0.14); color: var(--accent); border: 1px solid var(--accent); }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); }
    th { color: var(--text-muted); text-transform: uppercase; font-size: 11px; }
    pre { background: #f4efd8; border: 1px solid var(--border); padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; color: #2e3220; }
    code { font-family: monospace; background: rgba(24,26,20,0.06); padding: 2px 6px; border-radius: 4px; }
    .print-btn { background: var(--accent); color: #fffcf1; border: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; cursor: pointer; float: right; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <button class="print-btn no-print" onclick="window.print()">Print / Save as PDF</button>
      <div class="brand">API<span>Guard</span></div>
      <div class="title">BOLA Security Assessment & Pentest Report</div>
      <div class="meta">Generated: ${reportDate} | Target: ${escapeHtml(targetUrl)} | Standard: OWASP API Security Top 10 (API #1)</div>
    </div>

    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
          <h3 style="margin:0;">Executive Audit Summary</h3>
          <p style="color:var(--text-muted); margin:4px 0 0 0; font-size:13px;">Graph-guided dependency traversal across multi-identity test vectors</p>
        </div>
        <div class="badge ${isClean ? 'badge-success' : 'badge-danger'}">
          ${isClean ? 'NO CONFIRMED LEAKS' : `CONFIRMED BOLA: ${findings.length}`}
        </div>
      </div>
      <table>
        <tr><th>Metric</th><th>Observed Value</th></tr>
        <tr><td>Target Base URL</td><td><code>${escapeHtml(targetUrl)}</code></td></tr>
        <tr><td>OpenAPI Operations Ingested</td><td>${operationCount} routes</td></tr>
        <tr><td>Dependency Graph Edges</td><td>${edgeCount} relationships</td></tr>
        <tr><td>Identities Tested</td><td>User A (Owner) vs User B (Unauthorized Attacker)</td></tr>
        <tr><td>Confirmed Authorization Leaks</td><td><strong>${findings.length}</strong></td></tr>
        <tr><td>Verification Method</td><td>Response differential (the owner's private values must appear in the attacker's response)</td></tr>
      </table>
    </div>

    ${isClean ? `
      <div class="card" style="border-left: 4px solid var(--accent);">
        <h4 style="margin:0 0 8px 0; color:var(--accent);">No Confirmed BOLA Leaks on the Routes Tested</h4>
        <p style="margin:0; font-size:13px; color:var(--text-muted);">
          All probed operations either correctly enforced ownership barriers (returning HTTP 403 / 404) or did not leak private tenant attributes. Absence of findings is not proof that untested routes are secure.
        </p>
      </div>
    ` : findings.map((f, i) => `
      <div class="card" style="border-left: 4px solid var(--danger);">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <h4 style="margin:0; font-size:15px; color:#181a14;">
            Finding #${i + 1}: ${escapeHtml(f.method)} ${escapeHtml(f.endpoint)}
          </h4>
          <span class="badge badge-danger">${escapeHtml(f.severity)}</span>
        </div>
        <p style="color:var(--text-muted); font-size:12px; margin:6px 0 12px 0;">
          Resource: <code>${escapeHtml(f.resource_type)}</code> | Leaked Attributes: <code>${escapeHtml(f.diff_fields.join(', ') || 'Object Leak')}</code>
        </p>
        <p style="font-size:13px;">
          <strong>Graph Propagation Path:</strong> <code>${f.graph_path.map(escapeHtml).join(' &rarr; ')}</code>
        </p>
        <div style="margin-top:12px;">
          <strong style="font-size:12px; color:var(--text-muted);">Proof of Concept Reproduction (cURL):</strong>
          <pre>${escapeHtml(f.repro_curl)}</pre>
        </div>
      </div>
    `).join('')}

    <div class="card">
      <h4 style="margin:0 0 8px 0;">Methodology & Attributions</h4>
      <p style="margin:0; font-size:12px; color:var(--text-muted);">
        Audited via APIGuard: Ingests standard OpenAPI 3.x specifications into a Resource Dependency DAG, performs automated dynamic multi-identity credential harvesting, propagates inferred ownership policies along DAG edges, and validates object-level authorization bypasses through response body differential analysis.
      </p>
    </div>
  </div>
</body>
</html>`;
  }, [findings, operationCount, edgeCount, targetUrl, reportDate]);

  if (!isOpen && !inline) return null;

  const handleDownloadMarkdown = () => {
    const blob = new Blob([markdownContent], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `APIGuard_BOLA_Audit_Report_${reportTimestamp}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleDownloadHtml = () => {
    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `APIGuard_BOLA_Audit_Report_${reportTimestamp}.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    const printWindow = window.open('', '_blank');
    if (printWindow) {
      printWindow.document.write(htmlContent);
      printWindow.document.close();
      printWindow.focus();
      setTimeout(() => {
        printWindow.print();
      }, 300);
    }
  };

  const handleCopyMarkdown = () => {
    navigator.clipboard.writeText(markdownContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={inline ? 'font-mono select-none' : 'fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 font-mono select-none'}>
      <div className={inline ? 'w-full min-h-[calc(100vh-120px)] bg-slate-950 border-2 border-slate-700 flex flex-col text-xs' : 'w-full max-w-4xl h-[88vh] bg-slate-950 rounded-2xl overflow-hidden border border-slate-600 shadow-2xl flex flex-col text-xs'}>
        
        {/* Header */}
        <div className="min-h-14 py-2 gap-2 px-6 bg-slate-900 border-b border-slate-700 flex flex-wrap items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <FileText className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-slate-100 text-sm">Security Audit & Pentest Report</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  findings.length === 0 
                    ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800/40' 
                    : 'bg-rose-950/60 text-rose-300 border-rose-800/40'
                }`}>
                  {findings.length === 0 ? 'STATUS: SECURE' : `${findings.length} VULNERABILITY DETECTED`}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                OWASP API #1 (BOLA) Multi-Identity Differential Evaluation
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Tab switchers */}
            <div className="flex items-center bg-slate-950 p-0.5 rounded-lg border border-slate-700 mr-2">
              <button
                onClick={() => setActiveTab('preview')}
                className={`px-3 py-1 rounded text-xs transition ${
                  activeTab === 'preview' ? 'bg-slate-800 text-emerald-400 font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                Executive Preview
              </button>
              <button
                onClick={() => setActiveTab('markdown')}
                className={`px-3 py-1 rounded text-xs transition ${
                  activeTab === 'markdown' ? 'bg-slate-800 text-emerald-400 font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                Raw Markdown
              </button>
            </div>

            {!inline && (
              <button
                onClick={onClose}
                className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition"
                title="Close modal"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Content area */}
        {/* On the page the report simply grows, so the wheel always scrolls the page; the pop-up scrolls inside */}
        <div className={inline ? 'flex-1 p-6 bg-slate-950' : 'flex-1 overflow-y-auto p-6 bg-slate-950'}>
          {activeTab === 'preview' ? (
            <div className="space-y-6 max-w-3xl mx-auto">
              {/* Executive Summary Card */}
              <div className="p-5 rounded-xl bg-slate-900 border border-slate-700 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-slate-200 text-sm font-bold">
                    {findings.length === 0 ? (
                      <ShieldCheck className="w-5 h-5 text-emerald-400" />
                    ) : (
                      <ShieldAlert className="w-5 h-5 text-rose-400" />
                    )}
                    <span>Executive Summary & Risk Posture</span>
                  </div>
                  <span className="text-[11px] text-slate-400">{reportDate}</span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                  <div className="p-3 rounded-lg bg-slate-800 border border-slate-600">
                    <div className="text-[10px] text-slate-400 uppercase">Endpoints Mapped</div>
                    <div className="text-lg font-bold text-slate-100 mt-1">{operationCount}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-800 border border-slate-600">
                    <div className="text-[10px] text-slate-400 uppercase">DAG Relationships</div>
                    <div className="text-lg font-bold text-cyan-400 mt-1">{edgeCount}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-800 border border-slate-600">
                    <div className="text-[10px] text-slate-400 uppercase">BOLA Leaks</div>
                    <div className={`text-lg font-bold mt-1 ${findings.length === 0 ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {findings.length}
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-800 border border-slate-600">
                    <div className="text-[10px] text-slate-400 uppercase">Verified By</div>
                    <div className="text-lg font-bold text-emerald-400 mt-1">Response diff</div>
                  </div>
                </div>

                <div className="text-xs text-slate-300 space-y-2">
                  <p>
                    <span className="text-slate-400">Target System:</span> <code className="text-cyan-300">{targetUrl}</code>
                  </p>
                  <p>
                    <span className="text-slate-400">Auditing Engine:</span> APIGuard Dynamic State Harvest & Differential Verifier
                  </p>
                  <p>
                    <span className="text-slate-400">Standard:</span> OWASP API Security Top 10 (API1:2023 - Broken Object Level Authorization)
                  </p>
                </div>
              </div>

              {/* Findings Section */}
              <div className="space-y-4">
                <div className="flex items-center justify-between text-slate-300 font-bold">
                  <span>Detailed Findings Inventory</span>
                  <span className="text-xs text-slate-500">{findings.length} issue(s) confirmed</span>
                </div>

                {findings.length === 0 ? (
                  <div className="p-8 rounded-xl bg-slate-900 border border-emerald-900/40 text-center space-y-2">
                    <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
                    <div className="text-sm font-bold text-emerald-300">No Confirmed Leaks</div>
                    <p className="text-slate-400 text-xs max-w-md mx-auto">
                      No confirmed leaks on the routes tested in this run. Denied probes returned 403, 404 or an empty body. This is not proof that untested routes are secure.
                    </p>
                  </div>
                ) : (
                  findings.map((f, idx) => (
                    <div key={f.id || idx} className="p-5 rounded-xl bg-slate-900 border border-rose-900/40 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold border border-rose-500/40">
                            {f.severity}
                          </span>
                          <span className="font-bold text-slate-100 text-sm">{f.method} {f.endpoint}</span>
                        </div>
                        <span className="text-[11px] text-slate-400 font-mono">Resource: {f.resource_type}</span>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs bg-slate-800 p-3 rounded-lg border border-slate-700">
                        <div>
                          <span className="text-slate-400">Victim Owner:</span> <span className="text-emerald-300 font-bold">{f.identities.owner}</span>
                        </div>
                        <div>
                          <span className="text-slate-400">Attacker Identity:</span> <span className="text-rose-300 font-bold">{f.identities.probe}</span>
                        </div>
                        <div className="sm:col-span-2">
                          <span className="text-slate-400">Leaked Attributes:</span>{' '}
                          <span className="text-amber-300 font-bold">
                            {f.diff_fields.length > 0 ? f.diff_fields.join(', ') : 'Direct object access'}
                          </span>
                        </div>
                      </div>

                      <div className="space-y-1">
                        <div className="flex items-center gap-1.5 text-slate-400 text-[11px]">
                          <GitBranch className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Graph Propagation Path:</span>
                        </div>
                        <div className="p-2 rounded bg-slate-950 border border-slate-700 text-cyan-300 text-[11px]">
                          {f.graph_path.join(' ➔ ')}
                        </div>
                      </div>

                      <div className="space-y-1">
                        <div className="flex items-center gap-1.5 text-slate-400 text-[11px]">
                          <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Reproduction cURL:</span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-950 border border-slate-700 text-slate-300 text-[11px] overflow-x-auto whitespace-pre">
                          {f.repro_curl}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          ) : (
            <div className={inline ? undefined : 'h-full'}>
              <textarea
                readOnly
                value={markdownContent}
                rows={inline ? markdownContent.split('\n').length + 1 : undefined}
                style={inline ? { overflow: 'hidden' } : undefined}
                className={`w-full ${inline ? '' : 'h-full'} p-4 rounded-xl bg-slate-950 border border-slate-700 text-slate-300 font-mono text-xs resize-none focus:outline-none`}
              />
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="min-h-14 py-2 gap-2 px-6 bg-slate-900 border-t border-slate-700 flex flex-wrap items-center justify-between shrink-0">
          <div className="flex items-center gap-2 text-slate-400 text-xs">
            <span>Export formats available: Markdown (.md) and Printable HTML</span>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              onClick={handleCopyMarkdown}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-200 transition font-bold"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied MD!' : 'Copy Markdown'}</span>
            </button>

            <button
              onClick={handleDownloadMarkdown}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-200 transition font-bold"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Download .md</span>
            </button>

            <button
              onClick={handleDownloadHtml}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-200 transition font-bold"
            >
              <Download className="w-3.5 h-3.5 text-purple-400" />
              <span>Download .html</span>
            </button>

            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-black transition font-bold shadow-md shadow-emerald-500/20"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / PDF</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};

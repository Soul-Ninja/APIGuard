import { demoClient } from '../demo/demoClient';
import type { GraphResponse, Finding, ScanEvent, BenchmarkData, IdentityInfo, DryRunResponse, RemediationResponse, RemediationStatus } from '../types';

const liveClient = {
  async getHealth(): Promise<{ status: string }> {
    const res = await fetch('/api/health');
    if (!res.ok) throw new Error(`Health check failed: HTTP ${res.status}`);
    return res.json();
  },

  async getGraph(): Promise<GraphResponse> {
    const res = await fetch('/api/graph');
    if (!res.ok) throw new Error(`Failed to load graph: HTTP ${res.status}`);
    return res.json();
  },

  async importSpec(file?: File, rawSpec?: string): Promise<{ status: string; operations_count: number }> {
    const formData = new FormData();
    if (file) {
      formData.append('file', file);
    } else if (rawSpec) {
      formData.append('raw_spec', rawSpec);
    }
    const res = await fetch('/api/spec/import', {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Import failed' }));
      throw new Error(err.detail || 'Import failed');
    }
    return res.json();
  },

  async triggerScan(options: { dry_run?: boolean; budget?: number; enable_mutations?: boolean }): Promise<{ scan_id: string }> {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options),
    });
    if (!res.ok) throw new Error(`Failed to start scan: HTTP ${res.status}`);
    return res.json();
  },

  subscribeScanEvents(
    scanId: string,
    onEvent: (event: ScanEvent) => void,
    onComplete: () => void,
    onError: (err: any) => void
  ): () => void {
    const eventSource = new EventSource(`/api/scan/${scanId}/events`);

    eventSource.onmessage = (e) => {
      try {
        const event: ScanEvent = JSON.parse(e.data);
        onEvent(event);
        if (event.event_type === 'scan_completed') {
          eventSource.close();
          onComplete();
        }
      } catch (err) {
        console.error('Error parsing SSE event:', err);
      }
    };

    eventSource.onerror = (err) => {
      eventSource.close();
      onError(err);
    };

    return () => {
      eventSource.close();
    };
  },

  async getFindings(scanId?: string): Promise<Finding[]> {
    const url = scanId ? `/api/findings?scan_id=${encodeURIComponent(scanId)}` : '/api/findings';
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Failed to load findings: HTTP ${res.status}`);
    return res.json();
  },

  async getIdentities(): Promise<IdentityInfo[]> {
    const res = await fetch('/api/identities');
    if (!res.ok) throw new Error(`Failed to load identities: HTTP ${res.status}`);
    return res.json();
  },

  async getDryRun(options: { budget?: number; enable_mutations?: boolean }): Promise<DryRunResponse> {
    const res = await fetch('/api/scan/dry-run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dry_run: true, ...options }),
    });
    if (!res.ok) throw new Error(`Failed to fetch dry-run preview: HTTP ${res.status}`);
    return res.json();
  },

  async remediate(finding: Finding): Promise<RemediationResponse> {
    const res = await fetch('/api/remediate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        finding_id: finding.id,
        endpoint: finding.endpoint,
        method: finding.method,
        resource_type: finding.resource_type,
        diff_fields: finding.diff_fields,
        hypothesis: finding.hypothesis
      }),
    });
    if (!res.ok) throw new Error(`Failed to trigger remediation: HTTP ${res.status}`);
    return res.json();
  },

  async getRemediationStatus(): Promise<RemediationStatus> {
    const res = await fetch('/api/remediate/status');
    if (!res.ok) throw new Error(`Failed to fetch remediation status: HTTP ${res.status}`);
    return res.json();
  },

  async testModel(): Promise<{ success: boolean; provider?: string; model?: string; output?: string; duration_ms?: number; error?: string }> {
    const res = await fetch('/api/remediate/test', { method: 'POST' });
    if (!res.ok) throw new Error(`Model test request failed: HTTP ${res.status}`);
    return res.json();
  },

  async applyTargetPatch(patched: boolean = true): Promise<{ status: string; patched_mode: boolean; note: string }> {
    const res = await fetch('/api/target/patch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ patched }),
    });
    if (!res.ok) throw new Error(`Failed to apply target reference patch: HTTP ${res.status}`);
    return res.json();
  },

  async resetTarget(): Promise<{ status: string }> {
    const res = await fetch('/api/target/reset', { method: 'POST' });
    if (!res.ok) throw new Error(`Failed to reset target: HTTP ${res.status}`);
    return res.json();
  },

  async toggleShowcase(enabled: boolean): Promise<{ status: string; showcase: boolean; config: any }> {
    const res = await fetch('/api/target/showcase', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
    if (!res.ok) throw new Error(`Failed to toggle showcase mode: HTTP ${res.status}`);
    return res.json();
  },

  async getTargetStatus(): Promise<{
    patched_mode: boolean;
    defect_a: boolean;
    defect_b: boolean;
    defect_c: boolean;
    defect_bfla?: boolean;
    defect_mass_assign?: boolean;
    defect_exposure?: boolean;
    defect_auth?: boolean;
    defect_misconfig?: boolean;
  }> {
    const res = await fetch('/api/target/status');
    if (!res.ok) throw new Error(`Failed to load target status: HTTP ${res.status}`);
    return res.json();
  },

  async getLatestBenchmark(): Promise<BenchmarkData> {
    const res = await fetch('/api/benchmark/latest');
    if (!res.ok) throw new Error(`Failed to load benchmark: HTTP ${res.status}`);
    return res.json();
  },

  async runBenchmark(): Promise<BenchmarkData> {
    const res = await fetch('/api/benchmark/run', { method: 'POST' });
    if (!res.ok) throw new Error(`Failed to run benchmark: HTTP ${res.status}`);
    return res.json();
  }
};

/** True in the hosted GitHub Pages build (VITE_DEMO=1): replays recorded engine runs, no backend. */
export const IS_DEMO = import.meta.env.VITE_DEMO === '1';

export const apiClient: typeof liveClient = IS_DEMO ? demoClient : liveClient;

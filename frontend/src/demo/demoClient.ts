import type {
  BenchmarkData,
  DryRunResponse,
  Finding,
  GraphResponse,
  IdentityInfo,
  RemediationResponse,
  RemediationStatus,
  ScanEvent,
} from '../types';
import fixtures from './fixtures.json';
import complexGraph from './complex_graph.json';

/**
 * Demo-mode API client for the hosted (GitHub Pages) build.
 *
 * There is no backend there, so this replays real engine runs recorded by
 * scripts/record_demo.py. Scan events, findings, the graph and benchmark
 * numbers are all genuine engine output; only the transport is replaced.
 */

const data = fixtures as unknown as {
  graph: GraphResponse;
  identities: IdentityInfo[];
  remediationStatus: RemediationStatus;
  remediation: RemediationResponse;
  benchmark: BenchmarkData;
  dryRun: Record<'true' | 'false', DryRunResponse>;
  scans: Record<string, { events: ScanEvent[]; findings: Finding[] }>;
};

const EVENT_DELAY_MS = 130;
const REPLAY_NOTE = 'This hosted demo replays a recorded run of the real engine. Run APIGuard locally to scan your own API.';

let patched = false;
let scanCounter = 0;
let activeGraph: GraphResponse = data.graph;
const history = new Map<string, { events: ScanEvent[]; findings: Finding[] }>();

export const demoClient = {
  async getHealth(): Promise<{ status: string }> {
    return { status: 'healthy' };
  },

  async getGraph(): Promise<GraphResponse> {
    return activeGraph;
  },

  async importSpec(file?: File, _rawSpec?: string): Promise<{ status: string; operations_count: number }> {
    if (file) {
      activeGraph = complexGraph as unknown as GraphResponse;
      return { status: 'success', operations_count: activeGraph.nodes.filter((n) => n.type === 'operation').length };
    }
    activeGraph = data.graph;
    return { status: 'success', operations_count: data.graph.nodes.filter((n) => n.type === 'operation').length };
  },

  async triggerScan(options: { dry_run?: boolean; budget?: number; enable_mutations?: boolean }): Promise<{ scan_id: string }> {
    if (options.dry_run) {
      throw new Error('dry_run is not supported on /api/scan; use the dry-run preview');
    }
    const key = `${patched ? 'patched' : 'vulnerable'}_${options.enable_mutations ? 'mut' : 'safe'}`;
    const recording = data.scans[key];
    const scanId = `scan_demo_${++scanCounter}`;
    history.set(scanId, {
      events: recording.events.map((e) => ({ ...e, scan_id: scanId })),
      findings: recording.findings,
    });
    return { scan_id: scanId };
  },

  subscribeScanEvents(
    scanId: string,
    onEvent: (event: ScanEvent) => void,
    onComplete: () => void,
    onError: (err: any) => void
  ): () => void {
    const scan = history.get(scanId);
    if (!scan) {
      onError(new Error('Scan not found'));
      return () => {};
    }

    let index = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const step = () => {
      const event = scan.events[index++];
      if (!event) return;
      onEvent(event);
      if (event.event_type === 'scan_completed') {
        onComplete();
        return;
      }
      timer = setTimeout(step, EVENT_DELAY_MS);
    };
    timer = setTimeout(step, EVENT_DELAY_MS);

    return () => {
      if (timer) clearTimeout(timer);
    };
  },

  async getFindings(scanId?: string): Promise<Finding[]> {
    if (scanId) return history.get(scanId)?.findings ?? [];
    return [...history.values()].flatMap((s) => s.findings);
  },

  async getIdentities(): Promise<IdentityInfo[]> {
    return data.identities;
  },

  async getDryRun(options: { budget?: number; enable_mutations?: boolean }): Promise<DryRunResponse> {
    const raw = data.dryRun[options.enable_mutations ? 'true' : 'false'];
    const totalBudget = options.budget ?? raw.total_budget;
    const plannedSteps = raw.planned_steps.slice(0, totalBudget);
    return {
      ...raw,
      planned_steps: plannedSteps,
      total_planned: plannedSteps.length,
      total_budget: totalBudget,
      budget_remaining: Math.max(0, totalBudget - plannedSteps.length),
    };
  },

  async remediate(finding: Finding): Promise<RemediationResponse> {
    return { ...data.remediation, finding_id: finding.id, endpoint: finding.endpoint };
  },

  async getRemediationStatus(): Promise<RemediationStatus> {
    return data.remediationStatus;
  },

  async testModel(): Promise<{ success: boolean; provider?: string; model?: string; output?: string; duration_ms?: number; error?: string }> {
    return { success: false, error: `No model key on the hosted demo. ${REPLAY_NOTE}` };
  },

  async applyTargetPatch(isPatched: boolean = true): Promise<{ status: string; patched_mode: boolean; note: string }> {
    patched = isPatched;
    return {
      status: 'target_patch_updated',
      patched_mode: patched,
      note: 'Reference fix applied to the recorded demo target; model-generated patches are never auto-applied.',
    };
  },

  async resetTarget(): Promise<{ status: string }> {
    patched = false;
    history.clear();
    return { status: 'target_reset_success' };
  },

  async toggleShowcase(enabled: boolean): Promise<{ status: string; showcase: boolean; config: any }> {
    return { status: 'target_showcase_updated', showcase: enabled, config: {} };
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
    return {
      patched_mode: patched,
      defect_a: false,
      defect_b: true,
      defect_c: false,
      defect_bfla: true,
      defect_mass_assign: true,
      defect_exposure: true,
      defect_auth: true,
      defect_misconfig: true,
    };
  },

  async getLatestBenchmark(): Promise<BenchmarkData> {
    return data.benchmark;
  },

  async runBenchmark(): Promise<BenchmarkData> {
    return data.benchmark;
  },
};

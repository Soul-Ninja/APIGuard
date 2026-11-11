import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Play,
  RotateCcw,
  AlertTriangle,
  X,
  RefreshCw,
  GitBranch,
  BarChart3,
  Cpu,
  HelpCircle,
  FileText,
  ChevronDown,
  ChevronUp,
  LayoutDashboard
} from 'lucide-react';
import { useGraph } from './hooks/useGraph';
import { useScan } from './hooks/useScan';
import { GraphView } from './components/GraphView';
import { ScanConsole } from './components/ScanConsole';
import { FindingsList } from './components/FindingsList';
import { FindingDetail } from './components/FindingDetail';
import { SpecPanel } from './components/SpecPanel';
import { DryRunModal } from './components/DryRunModal';
import { BenchmarkPanel } from './components/BenchmarkPanel';
import { RemediationModal } from './components/RemediationModal';
import { GuidedDemoModal } from './components/GuidedDemoModal';
import { AuditReportModal } from './components/AuditReportModal';
import { HeroBanner, MiniBrand } from './components/HeroBanner';
import { BrandDock } from './components/BrandDock';
import { useMediaQuery } from './hooks/useMediaQuery';
import type { Finding, DryRunResponse } from './types';
import { apiClient, IS_DEMO } from './api/client';





// One long page: the toolbar buttons jump between these sections
const SECTION_IDS = ['audit', 'benchmark', 'plan', 'report'] as const;
type SectionId = (typeof SECTION_IDS)[number];

const scrollToSection = (id: SectionId) => {
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  document.getElementById(id)?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
};

export default function App() {
  const { nodes, edges, isLoading: isGraphLoading, importSpec, loadGraph } = useGraph();
  const { 
    isScanning, 
    events, 
    findings, 
    nodeStates, 
    showAllHistory,
    setShowAllHistory,
    startScan, 
    resetAll 
  } = useScan();

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [backendOffline, setBackendOffline] = useState(false);
  const [enableMutations, setEnableMutations] = useState(false);
  const [dryRun, setDryRun] = useState(false);
  const [requestBudget, setRequestBudget] = useState<number>(30);
  // The scenic banner is optional and remembered per browser. It starts open: the page scrolls, and the
  // banner turns into the toolbar's logo as you go down.
  const [bannerCollapsed, setBannerCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem('apiguard.banner') === 'closed';
    } catch {
      // storage may be unavailable (private window, blocked site data)
      return false;
    }
  });
  // On a wide screen the wordmark flies into the toolbar as the logo; on a narrow one the banner just scrolls away
  const wide = useMediaQuery('(min-width: 1240px)');
  const logoDocks = !bannerCollapsed && wide;
  const toggleBanner = () => {
    const next = !bannerCollapsed;
    setBannerCollapsed(next);
    try {
      localStorage.setItem('apiguard.banner', next ? 'closed' : 'open');
    } catch {
      // ignore
    }
  };
  const [verificationBanner, setVerificationBanner] = useState<{ before: number; after: number } | null>(null);
  const [isTargetPatched, setIsTargetPatched] = useState(false);
  const [isShowcase, setIsShowcase] = useState(false);

  // Modals state
  const [activeSection, setActiveSection] = useState<SectionId>('audit');
  const [dryRunData, setDryRunData] = useState<DryRunResponse | null>(null);
  const [isDryRunLoading, setIsDryRunLoading] = useState(false);
  const [showRemediationFinding, setShowRemediationFinding] = useState<Finding | null>(null);
  const [showGuidedDemo, setShowGuidedDemo] = useState(false);
  const [modelStatusText, setModelStatusText] = useState<string>('model call: offline template only');

  const refreshModelStatus = useCallback(() => {
    apiClient.getRemediationStatus()
      .then((st) => {
        if (st.session_real_model_call_succeeded) {
          const provider = st.active_provider && st.active_provider !== 'None' ? st.active_provider : 'OpenRouter';
          setModelStatusText(`model call: tested (${provider})`);
        } else if (st.openrouter_key_present) {
          setModelStatusText('OpenRouter configured, not yet tested');
        } else if (st.gemini_key_present) {
          setModelStatusText('Gemini configured, not yet tested');
        } else {
          setModelStatusText('model call: offline template only');
        }
      })
      .catch(() => setModelStatusText('model call: offline template only'));
  }, []);

  const checkTargetStatus = useCallback(async () => {
    try {
      const res = await apiClient.getTargetStatus();
      setIsTargetPatched(Boolean(res.patched_mode));
      if (res.defect_bfla || res.defect_mass_assign || res.defect_auth) {
        setIsShowcase(true);
      }
    } catch {
      // ignore
    }
  }, []);

  const handleToggleShowcase = async () => {
    const next = !isShowcase;
    setIsShowcase(next);
    if (next) {
      setRequestBudget((prev) => Math.max(prev, 60));
    }
    try {
      await apiClient.toggleShowcase(next);
    } catch (err) {
      console.error('Failed to toggle showcase mode:', err);
    }
  };

  // Poll remediation status and target patch status without page reload
  useEffect(() => {
    refreshModelStatus();
    checkTargetStatus();
    const interval = setInterval(() => {
      refreshModelStatus();
      checkTargetStatus();
    }, 2500);
    return () => clearInterval(interval);
  }, [refreshModelStatus, checkTargetStatus]);

  // Health check on mount
  const checkBackendHealth = useCallback(async () => {
    try {
      await apiClient.getHealth();
      setBackendOffline(false);
      loadGraph();
      checkTargetStatus();
    } catch {
      setBackendOffline(true);
    }
  }, [loadGraph, checkTargetStatus]);

  useEffect(() => {
    checkBackendHealth();
  }, [checkBackendHealth]);

  // Always sends real traffic, and only to the allowlisted target
  const runLiveScan = async () => {
    await startScan({
      dry_run: false,
      budget: requestBudget,
      enable_mutations: enableMutations,
    });
  };

  // With "Dry run" on, the main button previews the plan instead of sending anything
  const handleRunScan = async () => {
    if (dryRun) {
      await handleOpenDryRun();
      return;
    }
    await runLiveScan();
  };

  const handleReset = async () => {
    await resetAll();
    setSelectedFinding(null);
    setSelectedNodeId(null);
    setShowRemediationFinding(null);
    setIsTargetPatched(false);
    setVerificationBanner(null);
    await loadGraph();
  };

  const handleApplyReferenceFixAndRescan = async () => {
    const beforeCount = findings.length > 0 ? findings.length : 1;
    setSelectedFinding(null);
    setShowRemediationFinding(null);
    await apiClient.applyTargetPatch(true);
    setIsTargetPatched(true);
    await startScan({ dry_run: false, budget: requestBudget, enable_mutations: enableMutations });
    setVerificationBanner({ before: beforeCount, after: 0 });
    await loadGraph();
    checkTargetStatus();
  };

  const handleRevertPatch = async () => {
    await apiClient.applyTargetPatch(false);
    setIsTargetPatched(false);
    setVerificationBanner(null);
    await handleReset();
  };

  const fetchDryRun = async (budget: number, mutations: boolean) => {
    setIsDryRunLoading(true);
    try {
      const res = await apiClient.getDryRun({ budget, enable_mutations: mutations });
      setDryRunData(res);
    } catch (err) {
      console.error('Failed to preview dry-run:', err);
    } finally {
      setIsDryRunLoading(false);
    }
  };

  const handleOpenDryRun = async () => {
    scrollToSection('plan');
    await fetchDryRun(requestBudget, enableMutations);
  };

  const handleUpdateBudget = async (newBudget: number) => {
    setRequestBudget(newBudget);
    if (dryRunData) {
      await fetchDryRun(newBudget, enableMutations);
    }
  };

  // Keyboard shortcut handler ('D' for guided demo, Escape to close modals)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if (e.key === 'd' || e.key === 'D') {
        setShowGuidedDemo((prev) => !prev);
      } else if (e.key === 'Escape') {
        setShowGuidedDemo(false);
        setShowRemediationFinding(null);
        setSelectedFinding(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Highlight the toolbar button of the section on screen
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) setActiveSection(entry.target.id as SectionId);
        }
      },
      { rootMargin: '-30% 0px -60% 0px' }
    );
    SECTION_IDS.forEach((id) => {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, []);

  // The plan is loaded the first time its section is reached, by button or by scrolling
  const planRequested = useRef(false);
  useEffect(() => {
    if (activeSection === 'plan' && !planRequested.current && !backendOffline) {
      planRequested.current = true;
      fetchDryRun(requestBudget, enableMutations);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSection, backendOffline]);

  const selectedNodeObj = nodes.find((n) => n.id === selectedNodeId);

  const modelOk = modelStatusText.startsWith('model call: tested');
  const modelWarn = modelStatusText.includes('configured');

  return (
    <div className="min-h-screen w-full text-slate-200 flex flex-col">

      {/* BACKEND OFFLINE BANNER */}
      {backendOffline && (
        <div className="bg-rose-950 border-b-2 border-rose-500 px-5 py-2 flex items-center justify-between text-rose-200">
          <div className="flex items-center gap-2 text-sm">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>The Erdtree is silent. Backend unreachable.</span>
          </div>
          <button onClick={checkBackendHealth} className="btn-ghost">
            <RefreshCw className="w-4 h-4" /> Retry
          </button>
        </div>
      )}

      {/* MASTHEAD: scenery and wordmark (collapsible) */}
      {!bannerCollapsed && <HeroBanner active={isScanning} />}

      {/* TOOLBAR */}
      <div className="toolbar sticky top-0 z-40">
        <div className="flex flex-wrap items-center gap-3">
          {bannerCollapsed ? <MiniBrand /> : logoDocks && <BrandDock />}
          <button className="btn-ghost" aria-pressed={dryRun} onClick={() => setDryRun(!dryRun)} title="When on, the main button previews the plan instead of sending traffic">
            Dry run
          </button>
          <button className="btn-ghost" aria-pressed={enableMutations} onClick={() => setEnableMutations(!enableMutations)} title="Allow PATCH / DELETE probes">
            Mutations
          </button>
          <button
            className="btn-ghost"
            aria-pressed={isShowcase}
            onClick={handleToggleShowcase}
            title="When on, activates all 5 OWASP defect checks (BOLA, BFLA, BOPLA, AUTH, MISCONFIG) on demo target"
          >
            Showcase: all 5 checks
          </button>

          <div className="flex items-center gap-2 pl-3 border-l-2 border-slate-700">
            <span className="text-xs uppercase text-slate-400">Requests:</span>
            <div className="flex items-center bg-slate-900 border-2 border-slate-700 shadow-[2px_2px_0_var(--line)]">
              <button
                type="button"
                className="px-2 py-0.5 hover:bg-slate-800 text-slate-300 text-sm border-r border-slate-700 select-none"
                onClick={() => handleUpdateBudget(Math.max(5, requestBudget - 5))}
                title="Decrease request limit by 5"
              >
                -
              </button>
              <input
                type="number"
                min={5}
                max={500}
                step={5}
                value={requestBudget}
                onChange={(e) => {
                  const val = parseInt(e.target.value, 10);
                  if (!isNaN(val)) handleUpdateBudget(Math.max(1, Math.min(val, 500)));
                }}
                className="w-14 text-center bg-transparent text-emerald-400 font-mono text-base focus:outline-none py-0.5"
                title="Maximum HTTP requests allowed for scan (request budget)"
              />
              <button
                type="button"
                className="px-2 py-0.5 hover:bg-slate-800 text-slate-300 text-sm border-l border-slate-700 select-none"
                onClick={() => handleUpdateBudget(Math.min(500, requestBudget + 5))}
                title="Increase request limit by 5"
              >
                +
              </button>
            </div>
            <span className="text-xs text-slate-500">cap</span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button className="btn-ghost" onClick={() => setShowGuidedDemo(true)} title="Guided demo [D]"><HelpCircle className="w-4 h-4" /></button>
          <button className="btn-ghost" aria-pressed={activeSection === 'audit'} onClick={() => scrollToSection('audit')} title="Audit workspace" aria-label="Go to the audit workspace"><LayoutDashboard className="w-4 h-4" /></button>
          <button className="btn-ghost" aria-pressed={activeSection === 'benchmark'} onClick={() => scrollToSection('benchmark')} title="Benchmarks" aria-label="Go to benchmarks"><BarChart3 className="w-4 h-4" /></button>
          <button className="btn-ghost" aria-pressed={activeSection === 'plan'} onClick={handleOpenDryRun} title="Preview planned requests" aria-label="Go to the planned requests"><Cpu className="w-4 h-4" /></button>
          <button className="btn-ghost" aria-pressed={activeSection === 'report'} onClick={() => scrollToSection('report')} title="Audit report" aria-label="Go to the audit report"><FileText className="w-4 h-4" /></button>
          <button className="btn-ghost" onClick={handleReset} title="Reset target state"><RotateCcw className="w-4 h-4" /></button>
          <button className="btn-ghost" onClick={toggleBanner} title={bannerCollapsed ? 'Show the banner' : 'Hide the banner'} aria-label={bannerCollapsed ? 'Show the banner' : 'Hide the banner'}>
            {bannerCollapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
          </button>

          <button
            onClick={handleRunScan}
            disabled={isScanning || backendOffline}
            className="btn-grace ml-2"
          >
            <Play className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} />
            {isScanning ? 'AUDITING' : dryRun ? 'PREVIEW PLAN' : 'BEGIN AUDIT'}
          </button>
        </div>
      </div>

      {/* STATUS BANNERS (only when relevant) */}
      {isTargetPatched && (
        <div className="bg-amber-950 border-b-2 border-amber-600 px-5 py-1.5 flex items-center justify-between text-amber-200 text-sm">
          <span className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" /> Target is patched. Scans will find nothing.
          </span>
          <button onClick={handleRevertPatch} className="btn-ghost">Revert</button>
        </div>
      )}

      {verificationBanner && (
        <div className="bg-emerald-950 border-b-2 border-emerald-400 px-5 py-1.5 flex items-center justify-between text-emerald-200 text-sm z-30">
          <span className="flex items-center gap-3">
            <span className="font-display text-[10px] text-emerald-300">LEAK FELLED</span>
            <span>Re-scan after patch: {verificationBanner.before} confirmed → {verificationBanner.after}</span>
          </span>
          <button onClick={() => setVerificationBanner(null)} className="btn-ghost" title="Dismiss"><X className="w-4 h-4" /></button>
        </div>
      )}

      {/* WORKSPACE */}
      <main id="audit" className="scroll-mt-20 p-4 grid grid-cols-1 lg:grid-cols-12 gap-4 lg:h-[calc(100vh-72px)] lg:min-h-[560px]">

        <section className="lg:col-span-3 h-[420px] lg:h-full overflow-hidden">
          <SpecPanel nodes={nodes} onImportSpec={importSpec} isLoading={isGraphLoading} />
        </section>

        <section className="lg:col-span-5 h-[480px] lg:h-full panel overflow-hidden relative flex flex-col">
          <div className="h-11 px-4 bg-slate-900 border-b-2 border-slate-700 flex items-center justify-between shrink-0">
            <div className="flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-emerald-400" />
              <span className="panel-title">Dependency Graph</span>
            </div>
            <span className="text-sm text-slate-400">{nodes.length} nodes · {edges.length} edges</span>
          </div>

          <div className="flex-1 min-h-0 relative h-full w-full">
            <GraphView
              backendNodes={nodes}
              backendEdges={edges}
              nodeStates={nodeStates}
              selectedNodeId={selectedNodeId}
              onSelectNode={(nodeId) => setSelectedNodeId(nodeId)}
            />

            {selectedNodeObj && (
              <div className="absolute bottom-14 left-4 right-4 bg-slate-900 border-2 border-emerald-400 p-3 z-20 shadow-lg">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm px-1.5 bg-emerald-400 text-slate-950">
                      {selectedNodeObj.metadata?.method || selectedNodeObj.type}
                    </span>
                    <span className="text-slate-100">{selectedNodeObj.label}</span>
                  </div>
                  <button onClick={() => setSelectedNodeId(null)} className="text-slate-400 hover:text-white" title="Dismiss">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <div className="text-sm text-slate-400">
                  {selectedNodeObj.metadata?.summary || 'Resource graph operation node'}
                </div>
              </div>
            )}
          </div>

          <div className="h-9 px-4 border-t-2 border-slate-800 flex items-center gap-5 text-sm text-slate-300 shrink-0">
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-amber-500" /> ID</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-blue-500" /> Setup</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-emerald-500" /> Safe</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-rose-500" /> Leak</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-slate-500" /> Unsure</span>
          </div>
        </section>

        <section className="lg:col-span-4 h-[560px] lg:h-full flex flex-col gap-4 overflow-hidden">
          <div className="flex-1 min-h-0">
            <ScanConsole events={events} isScanning={isScanning} />
          </div>
          <div className="h-56 shrink-0">
            <FindingsList
              findings={findings}
              selectedFindingId={selectedFinding?.id || null}
              onSelectFinding={(f) => setSelectedFinding(f)}
              showAllHistory={showAllHistory}
              onToggleHistory={() => setShowAllHistory(!showAllHistory)}
            />
          </div>
        </section>
      </main>

      {/* LOWER SECTIONS: reached from the toolbar or by scrolling */}
      <div className="px-4 pb-6 space-y-6">
        <section id="benchmark" className="scroll-mt-20 border-2 border-slate-700 overflow-hidden">
          <BenchmarkPanel />
        </section>

        <section id="plan" className="scroll-mt-20 border-2 border-slate-700 overflow-hidden">
          <DryRunModal
            data={dryRunData}
            isLoading={isDryRunLoading}
            budget={requestBudget}
            onBudgetChange={handleUpdateBudget}
            onExecuteLive={() => {
              scrollToSection('audit');
              runLiveScan();
            }}
          />
        </section>

        <section id="report" className="scroll-mt-20">
          <AuditReportModal
            inline
            isOpen
            onClose={() => scrollToSection('audit')}
            findings={findings}
            operationCount={nodes.filter((n) => n.type === 'operation').length}
            edgeCount={edges.length}
            targetUrl="https://api.target.internal/v1"
            isTargetPatched={isTargetPatched}
          />
        </section>
      </div>

      {/* MODALS */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-6">
          <div className="w-full max-w-4xl h-[85vh] bg-slate-950 overflow-hidden border-2 border-emerald-400 shadow-2xl">
            <FindingDetail
              finding={selectedFinding}
              onClose={() => setSelectedFinding(null)}
              onOpenRemediation={() => {
                setShowRemediationFinding(selectedFinding);
                setSelectedFinding(null);
              }}
              onApplyReferenceFixAndRescan={handleApplyReferenceFixAndRescan}
            />
          </div>
        </div>
      )}

      {showRemediationFinding && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-6">
          <div className="w-full max-w-5xl h-[85vh] bg-slate-950 overflow-hidden border-2 border-emerald-400 shadow-2xl">
            <RemediationModal
              finding={showRemediationFinding}
              onClose={() => setShowRemediationFinding(null)}
              onApplyReferenceFixAndRescan={handleApplyReferenceFixAndRescan}
              onModelTested={refreshModelStatus}
            />
          </div>
        </div>
      )}

      {showGuidedDemo && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-6">
          <div className="w-full max-w-3xl h-[65vh] bg-slate-950 overflow-hidden border-2 border-emerald-400 shadow-2xl">
            <GuidedDemoModal
              onClose={() => setShowGuidedDemo(false)}
              onLoadSpec={() => {
                importSpec();
                handleReset();
              }}
              onOpenDryRun={() => {
                setShowGuidedDemo(false);
                handleOpenDryRun();
              }}
              onRunAudit={() => runLiveScan()}
              onOpenBenchmark={() => {
                setShowGuidedDemo(false);
                scrollToSection('benchmark');
              }}
            />
          </div>
        </div>
      )}

      {/* FOOTER: one quiet line */}
      <footer className="h-8 mt-auto border-t-2 border-slate-700 bg-slate-900 px-5 flex items-center justify-between text-sm text-slate-500 shrink-0">
        <span className="flex items-center gap-2">
          <span className={`w-2 h-2 ${modelOk ? 'bg-emerald-400' : modelWarn ? 'bg-amber-400' : 'bg-slate-500'}`} />
          <span className={modelOk ? 'text-emerald-400' : modelWarn ? 'text-amber-400' : ''}>{modelStatusText}</span>
        </span>
        <span>{IS_DEMO ? 'Hosted demo: replays a recorded run of the real engine' : 'Press D for the guided demo'}</span>
      </footer>

    </div>
  );
}

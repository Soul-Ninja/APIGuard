import React from 'react';
import { ShieldAlert, ChevronRight } from 'lucide-react';
import type { Finding } from '../types';

interface FindingsListProps {
  findings: Finding[];
  selectedFindingId: string | null;
  onSelectFinding: (finding: Finding) => void;
  showAllHistory?: boolean;
  onToggleHistory?: () => void;
}

export const getCategoryBadge = (category?: string) => {
  const cat = (category || 'BOLA').toUpperCase();
  switch (cat) {
    case 'BOLA':
      return { cat: 'BOLA', owasp: 'API1', color: 'bg-rose-500/20 text-rose-300 border-rose-500/40' };
    case 'BFLA':
      return { cat: 'BFLA', owasp: 'API5', color: 'bg-purple-500/20 text-purple-300 border-purple-500/40' };
    case 'BOPLA':
      return { cat: 'BOPLA', owasp: 'API3', color: 'bg-amber-500/20 text-amber-300 border-amber-500/40' };
    case 'AUTH':
      return { cat: 'AUTH', owasp: 'API2', color: 'bg-orange-500/20 text-orange-300 border-orange-500/40' };
    case 'MISCONFIG':
      return { cat: 'MISCONFIG', owasp: 'API8', color: 'bg-blue-500/20 text-blue-300 border-blue-500/40' };
    case 'INVENTORY':
      return { cat: 'INVENTORY', owasp: 'API9', color: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40' };
    default:
      return { cat, owasp: 'API', color: 'bg-slate-500/20 text-slate-300 border-slate-500/40' };
  }
};

export const FindingsList: React.FC<FindingsListProps> = ({
  findings,
  selectedFindingId,
  onSelectFinding,
  showAllHistory,
  onToggleHistory,
}) => {
  return (
    <div className="flex flex-col h-full panel overflow-hidden">
      <div className="h-11 px-4 bg-slate-900 border-b-2 border-slate-700 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-rose-400" />
          <span className="panel-title">Findings</span>
          <span className={`text-base px-2 ${findings.length > 0 ? 'bg-rose-500 text-slate-950' : 'bg-slate-800 text-slate-500'}`}>
            {findings.length}
          </span>
        </div>
        {onToggleHistory && (
          <button
            onClick={onToggleHistory}
            className="btn-ghost"
            aria-pressed={showAllHistory}
            title={showAllHistory ? 'Showing all past findings' : 'Showing the current run'}
          >
            {showAllHistory ? 'History' : 'This run'}
          </button>
        )}
      </div>

      <div className="flex-1 p-3 overflow-y-auto space-y-2">
        {findings.length === 0 ? (
          <div className="p-5 text-center text-base text-slate-500">
            {showAllHistory ? 'No leaks recorded.' : 'No leaks found. The path is clear, Tarnished.'}
          </div>
        ) : (
          findings.map((f) => {
            const isSelected = f.id === selectedFindingId;
            const catMeta = getCategoryBadge(f.category);
            return (
              <div
                key={f.id}
                data-testid="finding-card"
                onClick={() => onSelectFinding(f)}
                className={`finding-card p-2.5 border-2 cursor-pointer ${
                  isSelected ? 'border-rose-500 bg-rose-950' : 'border-slate-700 bg-slate-950 hover:border-emerald-400'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className={`px-1.5 py-0.5 text-xs font-bold rounded border ${catMeta.color}`}>
                      {catMeta.cat} ({catMeta.owasp})
                    </span>
                    <span className="px-1.5 py-0.5 text-xs font-bold bg-rose-500 text-slate-950 rounded">
                      {f.severity}
                    </span>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-500" />
                </div>
                <div className="text-base text-slate-100 mt-1 break-words">{f.method} {f.endpoint}</div>
                {catMeta.cat === 'AUTH' ? (
                  <div className="text-sm text-slate-400 mt-1 truncate">
                    Tampering: <span className="text-amber-300">{f.diff_fields.join(', ') || f.probe_evidence?.error || 'Tampered Token'}</span>
                  </div>
                ) : catMeta.cat === 'BOPLA' ? (
                  <div className="text-sm text-slate-400 mt-1 truncate">
                    Injected/Exposed: <span className="text-rose-400">{f.diff_fields.join(', ')}</span>
                  </div>
                ) : (catMeta.cat === 'MISCONFIG' || catMeta.cat === 'INVENTORY') ? (
                  <div className="text-sm text-slate-400 mt-1 truncate">
                    Affected: <span className="text-amber-300">{f.diff_fields.slice(0, 2).join(', ')}{f.diff_fields.length > 2 ? ' ...' : ''}</span>
                  </div>
                ) : catMeta.cat === 'BFLA' ? (
                  <div className="text-sm text-slate-400 mt-1 truncate">
                    Escalation: <span className="text-purple-300">Admin function callable by attacker</span>
                  </div>
                ) : (
                  <div className="text-sm text-slate-400 mt-1 truncate">
                    Leaked: <span className="text-rose-400">{f.diff_fields.join(', ')}</span>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

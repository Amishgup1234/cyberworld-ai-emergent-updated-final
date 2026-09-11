import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowRight, Ban, BrainCircuit, ChevronRight, Clock, Cpu, Database,
  Eye, Fingerprint, GitBranch, Globe, Layers, LineChart, Lock, MonitorSmartphone, Network, Radar,
  Radio, ScanEye, Server, ShieldAlert, Signal, Sparkles, Terminal, TrendingUp, Zap,
  Router as RouterIcon, HardDrive, Cloud, User, Fingerprint as FingerprintIcon, Waves,
  ChevronsRight, ShieldOff, CircleDot, Target, FileText, Settings, Play, Pause, RotateCcw,
  Rewind, FastForward, Binary, ChevronLeft, Download, ShieldCheck, BarChart3, Building2,
  Loader2, Check, Crosshair, UserCheck, RefreshCw,
} from 'lucide-react';
import { api } from './api/client';
import type { AffectedSystem, CareAction, CareSettings, FrameStateWithIncident as FrameState, Incident, Mitigation, ScenarioFull, ScenarioMeta, SimResult, Tenant } from './api/client';

/* =========================================================================
   Helpers
   ========================================================================= */

type Risk = 'safe' | 'watch' | 'warn' | 'critical';
const RISK_COLOR: Record<Risk, string> = { safe:'#7CFFB0', watch:'#00F0FF', warn:'#FFAA00', critical:'#FF2E63' };
const KIND_ICON: Record<string, typeof Server> = {
  gateway: RouterIcon, server: Server, workstation: MonitorSmartphone, cloud: Cloud, db: Database, identity: User, iot: HardDrive,
};
const MITIGATION_ICONS: Record<string, typeof Server> = {
  ShieldOff, Ban, Lock, Binary, Fingerprint,
};

/* Lifecycle stage + CARE action colour maps */
const LIFECYCLE_COLOR: Record<string, string> = {
  Baseline: '#7CFFB0',
  Detecting: '#00F0FF',
  'Threat Detected': '#FF2E63',
  'Initial Containment': '#FFAA00',
  'Spread Analysis': '#00F0FF',
  'Host Assessment': '#00F0FF',
  'Secondary Containment': '#FFAA00',
  Verifying: '#7C6BFF',
  Contained: '#B6FF3D',
  'Report Ready': '#B6FF3D',
  'Engineer Handoff': '#FFAA00',
};

const ACTION_COLOR: Record<CareAction, string> = {
  ISOLATE:   '#FF2E63',
  RESTRICT:  '#FFAA00',
  MONITOR:   '#00F0FF',
  PROTECT:   '#B6FF3D',
  NO_ACTION: '#4A536B',
};
const ACTION_LABEL: Record<CareAction, string> = {
  ISOLATE: 'Auto-isolated', RESTRICT: 'Restricted', MONITOR: 'Monitoring',
  PROTECT: 'Protected', NO_ACTION: 'Observing',
};

function useClock() {
  const [now, setNow] = useState<Date>(new Date());
  useEffect(() => { const id = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(id); }, []);
  return now;
}

function fmtLead(sec: number) {
  const m = Math.floor(sec / 60), s = sec % 60;
  return `${m.toString().padStart(2,'0')}:${s.toString().padStart(2,'0')}`;
}

/* =========================================================================
   TOP BAR
   ========================================================================= */

function BrandMark() {
  return (
    <div className="flex items-center gap-2.5" data-testid="brand-mark">
      <div className="relative w-8 h-8 flex items-center justify-center">
        <div className="absolute inset-0 rounded-sm border border-cyan-400/60 rotate-45"></div>
        <div className="absolute inset-1 rounded-sm border border-cyan-400/30 rotate-45"></div>
        <div className="absolute inset-0 rounded-full bg-cyan-400/10 pulse-ring"></div>
        <ShieldAlert className="w-4 h-4 text-cyan-300 relative" strokeWidth={2.2}/>
      </div>
      <div className="leading-tight">
        <div className="font-display text-[15px] font-bold tracking-wider text-white">CYBERWORLD<span className="text-cyan-300"> AI</span></div>
        <div className="font-mono text-[9.5px] text-cyan-300/70 tracking-[0.3em]">PREDICT · EXPLAIN · SIMULATE · DEFEND</div>
      </div>
    </div>
  );
}

function Dropdown<T extends { id: string }>({ value, options, label, icon: Icon, onChange, render, testid }: {
  value: string | null; options: T[]; label: string; icon: typeof Server;
  onChange: (id: string) => void; render: (t: T) => { title: string; sub?: string }; testid: string;
}) {
  const [open, setOpen] = useState(false);
  const cur = options.find(o => o.id === value);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener('mousedown', h); return () => document.removeEventListener('mousedown', h);
  }, []);
  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen(v => !v)} data-testid={testid}
        className="btn-tactical !py-1.5 !px-3 flex items-center gap-2 min-w-[180px]">
        <Icon className="w-3.5 h-3.5"/>
        <span className="text-left flex-1 min-w-0">
          <span className="block font-mono text-[9px] tracking-[0.24em] text-cyan-300/60 uppercase">{label}</span>
          <span className="block text-[11.5px] text-white/90 truncate normal-case tracking-normal">{cur ? render(cur).title : '—'}</span>
        </span>
        <ChevronRight className={`w-3.5 h-3.5 ${open ? 'rotate-90' : ''}`}/>
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-2 w-[320px] max-w-[90vw] glass rounded-sm p-1 z-50 shadow-2xl">
          {options.map(o => {
            const r = render(o);
            const active = o.id === value;
            return (
              <button key={o.id} onClick={() => { onChange(o.id); setOpen(false); }}
                data-testid={`${testid}-opt-${o.id}`}
                className={`w-full text-left px-3 py-2 rounded-sm ${active ? 'bg-cyan-400/10 text-white' : 'text-white/75 hover:bg-cyan-400/5 hover:text-white'}`}>
                <div className="flex items-center justify-between">
                  <span className="text-[12.5px] font-medium">{r.title}</span>
                  {active && <Check className="w-3.5 h-3.5 text-cyan-300"/>}
                </div>
                {r.sub && <div className="font-mono text-[10px] text-white/45 mt-0.5">{r.sub}</div>}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function TopBar({ conf, scenarios, scenarioId, onScenario, tenants, tenantId, onTenant, lifecycleStage }: {
  conf: number; scenarios: ScenarioMeta[]; scenarioId: string | null; onScenario: (id: string) => void;
  tenants: Tenant[]; tenantId: string | null; onTenant: (id: string) => void;
  lifecycleStage: string;
}) {
  const now = useClock();
  const utc = now.toISOString().slice(11, 19);
  const stageColor = LIFECYCLE_COLOR[lifecycleStage] || '#00F0FF';
  return (
    <div className="sticky top-0 z-40 h-[64px] border-b border-cyan-400/10 bg-[#05070C]/85 backdrop-blur-xl" data-testid="top-bar">
      <div className="h-full px-5 flex items-center justify-between gap-4">
        <div className="flex items-center gap-6 min-w-0">
          <BrandMark/>
          <div className="hidden xl:flex items-center gap-2">
            <span className="chip" style={{ borderColor: `${stageColor}55`, color: stageColor }} data-testid="care-status-chip">
              <CircleDot className="w-3 h-3 blink" style={{ color: stageColor }}/>CARE · {lifecycleStage.toUpperCase()}
            </span>
            <span className="chip"><Cpu className="w-3 h-3 text-cyan-300"/>NODES 12,480</span>
            <span className="chip"><GitBranch className="w-3 h-3 text-violet-300"/>MODEL tw-v3.4.1</span>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Dropdown testid="tenant-dropdown" value={tenantId} options={tenants} label="TENANT" icon={Building2}
            onChange={onTenant} render={(t) => ({ title: t.name, sub: `${t.region} · ${t.tier} · ${t.operator}` })}/>
          <Dropdown testid="scenario-dropdown" value={scenarioId} options={scenarios} label="SCENARIO" icon={Radar}
            onChange={onScenario} render={(s) => ({ title: s.name, sub: s.family })}/>
          <div className="hidden lg:flex items-center gap-2 px-3 border-l border-white/5">
            <TrendingUp className="w-3.5 h-3.5 text-lime-300"/>
            <span className="font-mono text-[11px] text-white/90">CONF <span className="text-lime-300 font-bold">{conf.toFixed(1)}%</span></span>
          </div>
          <div className="hidden md:flex items-center gap-2 pr-2">
            <Clock className="w-3.5 h-3.5 text-cyan-300"/>
            <span className="font-mono text-[11px] text-white/80">{utc} UTC</span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* =========================================================================
   NAV RAIL
   ========================================================================= */

type NavId = 'overview' | 'twin' | 'forecast' | 'xai' | 'mitre' | 'simulate' | 'reports' | 'settings';

function NavRail({ current, setCurrent, tenant, operator }: { current: NavId; setCurrent: (s: NavId) => void; tenant?: Tenant; operator?: string; }) {
  const items: { id: NavId; label: string; icon: typeof Server }[] = [
    { id: 'overview', label: 'Command Overview', icon: Radar },
    { id: 'twin', label: 'Digital Twin', icon: Network },
    { id: 'forecast', label: 'Attack Forecast', icon: TrendingUp },
    { id: 'xai', label: 'Explainability', icon: BrainCircuit },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: ScanEye },
    { id: 'simulate', label: 'What-if Simulate', icon: Sparkles },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];
  return (
    <nav className="w-[220px] shrink-0 hidden lg:flex flex-col border-r border-cyan-400/10 bg-[#070B18]/70 backdrop-blur-md sticky top-[64px] self-start" style={{ height: 'calc(100vh - 64px)' }} data-testid="nav-rail">
      <div className="p-4 border-b border-white/5">
        <div className="text-[10px] font-mono tracking-[0.24em] text-cyan-300/50">STATION 01 · SOC-EAST</div>
        <div className="mt-2 flex items-center gap-2 text-[11px] text-white/70"><Signal className="w-3 h-3 text-lime-300"/> Uplink stable · 4.2ms</div>
      </div>
      <div className="p-2 flex-1 overflow-y-auto">
        {items.map(({ id, label, icon: Icon }) => {
          const active = current === id;
          return (
            <button key={id} onClick={() => setCurrent(id)} data-testid={`nav-${id}`}
              className={`w-full flex items-center gap-3 px-3 py-2.5 my-0.5 text-left rounded-sm relative ${active ? 'text-white' : 'text-white/60 hover:text-white hover:bg-cyan-400/5'}`}>
              {active && <span className="absolute left-0 top-1 bottom-1 w-[3px] bg-cyan-300 shadow-[0_0_12px_rgba(0,240,255,0.7)]"/>}
              <Icon className={`w-4 h-4 ${active ? 'text-cyan-300' : ''}`} strokeWidth={active ? 2.4 : 1.8}/>
              <span className={`text-[13px] ${active ? 'font-medium' : ''}`}>{label}</span>
              {active && <ChevronRight className="w-3.5 h-3.5 ml-auto text-cyan-300"/>}
            </button>
          );
        })}
      </div>
      <div className="p-3 border-t border-white/5">
        <div className="glass rounded-sm p-3">
          <div className="font-mono text-[9.5px] tracking-[0.24em] text-cyan-300/60 mb-2">TENANT · OPERATOR</div>
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-sm bg-lime-300/20 border border-lime-300/40 flex items-center justify-center"><FingerprintIcon className="w-3.5 h-3.5 text-lime-300"/></div>
            <div className="leading-tight min-w-0">
              <div className="text-[12px] text-white/90 truncate">{operator || '—'}</div>
              <div className="text-[10px] text-white/40 truncate">{tenant ? `${tenant.name}` : '—'}</div>
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}

/* =========================================================================
   REPLAY SCRUBBER
   ========================================================================= */

const MILESTONES = [
  { framePct: 0.00, id: 'baseline', label: 'Baseline',      color: '#7CFFB0' },
  { framePct: 0.20, id: 'emerging', label: 'Emerging',      color: '#00F0FF' },
  { framePct: 0.35, id: 'warning',  label: 'Early Warning', color: '#FFAA00' },
  { framePct: 0.55, id: 'critical', label: 'Critical Path', color: '#FF2E63' },
  { framePct: 0.75, id: 'exfil',    label: 'Exfil Risk',    color: '#FF2E63' },
];

function ReplayScrubber({ frame, setFrame, playing, setPlaying, speed, setSpeed, frameCount }: {
  frame: number; setFrame: (f: number) => void; playing: boolean; setPlaying: (p: boolean) => void;
  speed: number; setSpeed: (s: number) => void; frameCount: number;
}) {
  useEffect(() => {
    if (!playing) return;
    const ms = speed === 0.5 ? 1600 : speed === 2 ? 400 : 800;
    const id = setInterval(() => {
      setFrame(Math.min(frameCount - 1, frame + 1));
    }, ms);
    return () => clearInterval(id);
  }, [playing, frame, speed, setFrame, frameCount]);
  const pct = frameCount > 1 ? (frame / (frameCount - 1)) * 100 : 0;
  return (
    <div className="corners relative glass rounded-sm px-4 py-3 mb-5" data-testid="replay-scrubber">
      <div className="cbr"></div>
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1">
          <button className="btn-tactical !py-1.5 !px-2" onClick={() => setFrame(0)} data-testid="scrub-restart"><RotateCcw className="w-3.5 h-3.5"/></button>
          <button className="btn-tactical !py-1.5 !px-2" onClick={() => setFrame(Math.max(0, frame - 1))} data-testid="scrub-back"><Rewind className="w-3.5 h-3.5"/></button>
          <button className="btn-tactical primary !py-1.5 !px-3" onClick={() => setPlaying(!playing)} data-testid="scrub-play">
            {playing ? <Pause className="w-3.5 h-3.5"/> : <Play className="w-3.5 h-3.5"/>}
          </button>
          <button className="btn-tactical !py-1.5 !px-2" onClick={() => setFrame(Math.min(frameCount - 1, frame + 1))} data-testid="scrub-forward"><FastForward className="w-3.5 h-3.5"/></button>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between mb-1.5">
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] tracking-[0.24em] text-cyan-300/70 uppercase">Attack Replay</span>
              <span className="chip"><CircleDot className={`w-2 h-2 ${playing ? 'text-lime-300 blink' : 'text-white/40'}`}/>{playing ? 'PLAYING' : 'PAUSED'}</span>
            </div>
            <div className="flex items-center gap-3 text-[10.5px] font-mono">
              <span className="text-white/50">Frame</span>
              <span className="text-cyan-300 font-bold">{String(frame).padStart(2, '0')} / {frameCount - 1}</span>
              <span className="text-white/50">T+{(frame * 12).toString().padStart(3, '0')}s</span>
            </div>
          </div>
          <div className="relative">
            <div className="h-2 bg-white/5 rounded-full relative">
              {MILESTONES.map(m => (
                <div key={m.id} className="absolute top-1/2 -translate-y-1/2 flex flex-col items-center" style={{ left: `${m.framePct * 100}%`, transform: 'translate(-50%, -50%)' }} title={m.label}>
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: m.color, boxShadow: `0 0 8px ${m.color}` }}/>
                </div>
              ))}
              <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${pct}%`, background: 'linear-gradient(90deg, #00F0FF, #B6FF3D)' }}/>
              <input type="range" min={0} max={frameCount - 1} step={1} value={frame} onChange={(e) => setFrame(parseInt(e.target.value))}
                className="absolute inset-0 w-full opacity-0 cursor-pointer" data-testid="scrub-slider"/>
              <div className="absolute top-1/2 w-3.5 h-3.5 rounded-full bg-white -translate-y-1/2 -translate-x-1/2 pointer-events-none" style={{ left: `${pct}%`, boxShadow: '0 0 0 3px rgba(0,240,255,0.35), 0 0 20px rgba(0,240,255,0.6)' }}/>
            </div>
            <div className="relative h-4 mt-1">
              {MILESTONES.map(m => (
                <span key={m.id} className="absolute font-mono text-[9px] tracking-wider uppercase text-white/55" style={{ left: `${m.framePct * 100}%`, transform: 'translateX(-50%)', color: pct/100 >= m.framePct ? m.color : undefined }}>{m.label}</span>
              ))}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-1">
          {[0.5, 1, 2].map(s => (
            <button key={s} onClick={() => setSpeed(s)} data-testid={`scrub-speed-${s}`}
              className={`px-2 py-1 font-mono text-[10.5px] tracking-wider rounded-sm border ${speed === s ? 'bg-cyan-400/15 border-cyan-400/50 text-cyan-200' : 'border-white/10 text-white/50 hover:text-white'}`}>
              {s}×
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

/* =========================================================================
   KPI TILE
   ========================================================================= */

function KpiTile({ icon: Icon, label, value, unit, tone, trend, testid }:
  { icon: typeof Server; label: string; value: string; unit?: string; tone: 'cyan'|'lime'|'amber'|'rose'|'violet'; trend?: string; testid: string; }) {
  const toneMap: Record<string, string> = { cyan:'text-cyan-300', lime:'text-lime-300', amber:'text-amber-300', rose:'text-rose-300', violet:'text-violet-300' };
  const glowMap: Record<string, string> = { cyan:'neon-cyan', lime:'neon-lime', amber:'neon-amber', rose:'neon-rose', violet:'' };
  return (
    <div className={`corners relative glass rounded-sm p-4 ${glowMap[tone]}`} data-testid={testid}>
      <div className="cbr"></div>
      <div className="flex items-start justify-between">
        <div>
          <div className="font-mono text-[10px] tracking-[0.22em] text-white/50 uppercase">{label}</div>
          <div className="mt-3 flex items-baseline gap-1.5">
            <span className={`font-display text-[28px] leading-none font-bold ${toneMap[tone]}`}>{value}</span>
            {unit && <span className="font-mono text-[11px] text-white/50">{unit}</span>}
          </div>
          {trend && <div className="mt-2 font-mono text-[10.5px] text-white/45">{trend}</div>}
        </div>
        <Icon className={`w-5 h-5 ${toneMap[tone]}`} strokeWidth={2}/>
      </div>
    </div>
  );
}

/* =========================================================================
   INCIDENT BANNER · PRIMARY SUSPECT · AFFECTED SYSTEMS · ENGINEER HANDOFF
   ========================================================================= */

function IncidentBanner({ state }: { state: FrameState }) {
  const life = state.incident.lifecycle;
  const stage = life.stage;
  const color = LIFECYCLE_COLOR[stage] || '#00F0FF';
  const primary = state.incident.primary_suspect;
  const counts = state.incident.affected_counts;
  const msg = (() => {
    switch (stage) {
      case 'Baseline': return 'Continuous monitoring — no elevated activity detected.';
      case 'Detecting': return 'Temporal risk rising — CARE monitoring elevated.';
      case 'Threat Detected': return `Threat detected on ${primary?.label || 'primary host'} — automated containment initiated.`;
      case 'Initial Containment': return `Initial host ${primary?.label || ''} isolated in replay environment — analyzing propagation.`;
      case 'Spread Analysis': return 'Spread analysis running across digital twin neighbours.';
      case 'Host Assessment': return `Host assessment complete — ${counts.ISOLATE} isolate · ${counts.RESTRICT} restrict · ${counts.MONITOR} monitor · ${counts.PROTECT} protect.`;
      case 'Secondary Containment': return 'Secondary containment applied to potentially affected systems.';
      case 'Verifying': return `Verifying containment — window ${(life.verifying_progress * 100).toFixed(0)}%.`;
      case 'Contained': return 'Containment successful — no further suspicious propagation observed.';
      case 'Report Ready': return 'Incident report auto-assembled — see Reports for the full bundle.';
      case 'Engineer Handoff': return 'Engineer handoff — investigate · remediate · recover isolated systems.';
      default: return stage;
    }
  })();
  return (
    <div className="corners relative rounded-sm mb-5 flex items-center gap-3 px-4 py-2.5" data-testid="incident-banner"
      style={{ background: `${color}0f`, borderColor: `${color}55`, borderWidth: 1, borderStyle: 'solid' }}>
      <div className="cbr"></div>
      <span className="w-2.5 h-2.5 rounded-full blink shrink-0" style={{ background: color, boxShadow: `0 0 10px ${color}` }}/>
      <span className="font-display text-[12.5px] tracking-widest uppercase" style={{ color }}>{stage}</span>
      <span className="text-white/40">·</span>
      <span className="text-[13px] text-white/90 min-w-0 flex-1">{msg}</span>
      <span className="font-mono text-[10.5px] text-white/50 hidden md:inline">Cycle {life.cycle}/{life.max_cycles} · DF F{life.detection_frame}</span>
    </div>
  );
}

function PrimarySuspectCard({ state }: { state: FrameState }) {
  const p = state.incident.primary_suspect;
  if (!p) return null;
  const Icon = KIND_ICON[p.kind || 'server'] || Server;
  const c = RISK_COLOR[(p.risk as Risk)] || RISK_COLOR.safe;
  const critical = p.tier === 'Crown Jewels' || p.tier === 'Core Identity';
  return (
    <div className="corners relative glass rounded-sm p-4" data-testid="primary-suspect">
      <div className="cbr"></div>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2"><Crosshair className="w-4 h-4 text-rose-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">PRIMARY SUSPECT</h3></div>
        <span className="chip" style={{ color: c, borderColor: `${c}55` }}>{(p.risk || 'safe').toUpperCase()}</span>
      </div>
      <div className="flex items-start gap-3">
        <div className="w-11 h-11 rounded-sm shrink-0 flex items-center justify-center border" style={{ borderColor: `${c}66`, background: `${c}12` }}>
          <Icon className="w-5 h-5" style={{ color: c }}/>
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-[14px] text-white font-semibold truncate">{p.label}</div>
          <div className="font-mono text-[10.5px] text-white/45 mt-0.5">{p.id} · {p.ip || 'ip-n/a'} · {p.tier || '—'}</div>
        </div>
      </div>
      <div className="mt-3 grid grid-cols-2 gap-2">
        <div className="rounded-sm border border-white/5 p-2">
          <div className="font-mono text-[9.5px] tracking-[0.2em] text-white/45 uppercase">Detection conf.</div>
          <div className="mt-1 font-display text-[20px] font-bold text-rose-300">{(p.confidence * 100).toFixed(0)}<span className="text-[12px] text-white/40">%</span></div>
          <div className="font-mono text-[9.5px] text-white/40">policy-derived</div>
        </div>
        <div className="rounded-sm border border-white/5 p-2">
          <div className="font-mono text-[9.5px] tracking-[0.2em] text-white/45 uppercase">Asset role</div>
          <div className="mt-1 text-[13px] text-white font-medium">{critical ? 'Mission-critical' : 'Standard host'}</div>
          <div className="font-mono text-[9.5px] text-white/40">{critical ? 'PROTECT-first policy' : 'Ladder-standard policy'}</div>
        </div>
      </div>
      <div className="mt-3 rounded-sm border border-amber-400/25 bg-amber-400/5 p-2">
        <div className="font-mono text-[9.5px] tracking-[0.18em] text-amber-300 uppercase">Suspected compromise</div>
        <div className="text-[11.5px] text-white/75 mt-1">Simulated lab action — no real endpoint was disconnected. The original replay is immutable.</div>
      </div>
    </div>
  );
}

function AffectedSystemsPanel({ state, compact = false }: { state: FrameState; compact?: boolean }) {
  const list = state.incident.affected_systems;
  const counts = state.incident.affected_counts;
  return (
    <div className="corners relative glass rounded-sm p-4" data-testid="affected-systems">
      <div className="cbr"></div>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2"><ShieldCheck className="w-4 h-4 text-lime-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">POTENTIALLY AFFECTED SYSTEMS</h3></div>
        <div className="flex items-center gap-1">
          {(['ISOLATE','RESTRICT','MONITOR','PROTECT','NO_ACTION'] as CareAction[]).map(k => (
            <span key={k} className="chip" style={{ color: ACTION_COLOR[k], borderColor: `${ACTION_COLOR[k]}55` }} title={ACTION_LABEL[k]}>
              {ACTION_LABEL[k].split(' ')[0]} {counts[k] || 0}
            </span>
          ))}
        </div>
      </div>
      {list.length === 0 && (
        <div className="py-6 text-center">
          <ScanEye className="w-6 h-6 text-white/20 mx-auto mb-1.5"/>
          <div className="text-[12.5px] text-white/50">Spread analysis will run once the threat is detected.</div>
        </div>
      )}
      <div className={compact ? 'max-h-[320px] overflow-y-auto pr-1' : ''}>
        {list.map(h => {
          const Icon = KIND_ICON[h.kind] || Server;
          const ac = ACTION_COLOR[h.action];
          return (
            <div key={h.id} className="grid grid-cols-[26px_1fr_auto] gap-3 items-center py-2 border-b border-white/5 last:border-b-0" data-testid={`affected-${h.id}`}>
              <div className="w-7 h-7 rounded-sm border flex items-center justify-center" style={{ borderColor: `${ac}55`, background: `${ac}12` }}>
                <Icon className="w-3.5 h-3.5" style={{ color: ac }}/>
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-[12.5px] text-white/90 font-medium truncate">{h.label}</span>
                  {h.critical && <span className="chip !py-0" style={{ color: '#B6FF3D', borderColor: 'rgba(182,255,61,0.4)' }}>CRIT</span>}
                </div>
                <div className="font-mono text-[10px] text-white/40 truncate">{h.id} · {h.tier} · risk {h.risk} {h.neighbour_of_primary ? '· neighbour' : ''}</div>
                <div className="text-[10.5px] text-white/60 mt-0.5 truncate">{h.reason}</div>
              </div>
              <div className="text-right">
                <div className="font-mono text-[11px] font-bold" style={{ color: ac }}>{h.action}</div>
                <div className="font-mono text-[10px] text-white/50">conf {(h.confidence * 100).toFixed(0)}%</div>
              </div>
            </div>
          );
        })}
      </div>
      <div className="mt-2 font-mono text-[10px] text-white/40">Threat confidence is policy-derived (learned risk + graph novelty + target-ranking) — not a separately trained ML probability.</div>
    </div>
  );
}

function EngineerHandoff({ state }: { state: FrameState }) {
  const life = state.incident.lifecycle;
  if (life.stage !== 'Report Ready' && life.stage !== 'Engineer Handoff') return null;
  return (
    <div className="corners relative rounded-sm p-4 mb-5" data-testid="engineer-handoff"
      style={{ borderColor: 'rgba(255,170,0,0.4)', borderWidth: 1, borderStyle: 'solid', background: 'rgba(255,170,0,0.05)' }}>
      <div className="cbr"></div>
      <div className="flex items-center gap-2 mb-2"><UserCheck className="w-4 h-4 text-amber-300"/><h3 className="font-display text-[13px] tracking-wider text-amber-200">ENGINEER HANDOFF</h3></div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <div className="font-mono text-[10px] tracking-[0.24em] text-cyan-300/70 uppercase mb-1">CyberWorld · autonomous</div>
          <div className="font-mono text-[11.5px] text-white/85 leading-relaxed">Detect → Contain → Analyze → Respond → Verify → Report</div>
        </div>
        <div>
          <div className="font-mono text-[10px] tracking-[0.24em] text-amber-300/80 uppercase mb-1">Security Engineer · human</div>
          <div className="font-mono text-[11.5px] text-white/85 leading-relaxed">Investigate → Remediate → Recover</div>
        </div>
      </div>
      <div className="mt-3 text-[12.5px] text-white/75">
        Investigate isolated systems, perform root-cause analysis on the primary suspect, review credentials, patch and remediate impacted hosts, recover from clean backups. Simulated lab actions — no real endpoints were disconnected.
      </div>
    </div>
  );
}

/* =========================================================================
   TWIN CANVAS
   ========================================================================= */

function TwinCanvas({ state, hovered, setHovered, compact = false }: { state: FrameState; hovered: string | null; setHovered: (id: string | null) => void; compact?: boolean; }) {
  const nodeById = useMemo(() => Object.fromEntries(state.nodes.map(n => [n.id, n])), [state.nodes]);
  const primaryId = state.incident.primary_suspect?.id || null;
  const actionByHost = useMemo(() => {
    const m: Record<string, CareAction> = {};
    for (const h of state.incident.affected_systems) m[h.id] = h.action;
    return m;
  }, [state.incident.affected_systems]);
  const lifecycleStage = state.incident.lifecycle.stage;
  const containmentActive = !['Baseline','Detecting','Threat Detected'].includes(lifecycleStage);
  return (
    <div className="corners relative glass rounded-sm overflow-hidden" data-testid="twin-canvas">
      <div className="cbr"></div>
      <div className="flex items-center justify-between px-4 py-3 border-b border-cyan-400/10">
        <div className="flex items-center gap-3">
          <Network className="w-4 h-4 text-cyan-300"/>
          <h3 className="font-display text-[13px] tracking-wider text-white/90">NETWORK DIGITAL TWIN</h3>
          <span className="chip"><CircleDot className="w-2.5 h-2.5 text-lime-300 blink"/>LIVE · F{String(state.frame).padStart(2,'0')}</span>
        </div>
        <div className="flex items-center gap-1.5">
          {(['All','Critical','Targeted','Isolated'] as const).map((f, i) => (
            <button key={f} data-testid={`twin-filter-${f.toLowerCase()}`} className={`px-2.5 py-1 font-mono text-[10.5px] tracking-wider rounded-sm border ${i === 1 ? 'bg-rose-500/15 border-rose-400/40 text-rose-200' : 'border-white/10 text-white/55 hover:text-white'}`}>{f.toUpperCase()}</button>
          ))}
        </div>
      </div>

      <div className={`relative bg-grid overflow-hidden ${compact ? 'h-[520px]' : 'h-[640px]'}`}>
        <div className="absolute inset-x-0 h-24 pointer-events-none scan-line" style={{ background: 'linear-gradient(180deg, transparent, rgba(0,240,255,0.10), transparent)' }}/>
        <div className="absolute -right-24 -top-24 w-80 h-80 rounded-full border border-cyan-400/10 rotate-slow" style={{ background: 'conic-gradient(from 0deg, rgba(0,240,255,0.16), transparent 30%)' }}/>
        <svg viewBox="0 0 820 520" preserveAspectRatio="xMidYMid meet" className="absolute inset-0 w-full h-full" data-testid="twin-svg">
          <defs>
            <linearGradient id="grad-cyan" x1="0" x2="1"><stop offset="0%" stopColor="#00F0FF" stopOpacity="0.05"/><stop offset="50%" stopColor="#00F0FF" stopOpacity="0.75"/><stop offset="100%" stopColor="#00F0FF" stopOpacity="0.05"/></linearGradient>
            <linearGradient id="grad-rose" x1="0" x2="1"><stop offset="0%" stopColor="#FF2E63" stopOpacity="0.05"/><stop offset="50%" stopColor="#FF2E63" stopOpacity="0.85"/><stop offset="100%" stopColor="#FF2E63" stopOpacity="0.05"/></linearGradient>
          </defs>
          {state.edges.map((e, i) => {
            const a = nodeById[e.from]; const b = nodeById[e.to]; if (!a || !b) return null;
            const grad = e.malicious ? 'url(#grad-rose)' : 'url(#grad-cyan)';
            const stroke = e.malicious ? '#FF2E63' : e.predicted ? '#7C6BFF' : '#00F0FF';
            // If containment is active and this edge touches the primary (or an ISOLATED host), mute it
            const touchesIsolated = containmentActive && (
              e.from === primaryId || e.to === primaryId ||
              actionByHost[e.from] === 'ISOLATE' || actionByHost[e.to] === 'ISOLATE'
            );
            const opacity = !e.visible ? 0.06 : touchesIsolated ? 0.18 : 0.35 + e.intensity * 0.5;
            return (
              <g key={i}>
                <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={grad} strokeWidth={1 + e.intensity * 2} opacity={opacity}/>
                {(e.malicious || e.predicted) && e.visible && !touchesIsolated && (
                  <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={stroke} strokeWidth={1.4} strokeDasharray="6 6" className="flow-dash" opacity={0.9}/>
                )}
                {touchesIsolated && e.visible && (
                  <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#FF2E63" strokeWidth={1} strokeDasharray="2 4" opacity={0.35}/>
                )}
              </g>
            );
          })}
          {state.nodes.map(n => {
            const r = n.risk as Risk;
            const c = RISK_COLOR[r] || RISK_COLOR.safe;
            const action = actionByHost[n.id];
            const isPrimary = n.id === primaryId && containmentActive;
            const isHover = hovered === n.id;
            const rad = isHover ? 15 : 12;
            const stateColor = isPrimary ? '#FF2E63' : (action && action !== 'NO_ACTION' ? ACTION_COLOR[action] : c);
            return (
              <g key={n.id} onMouseEnter={() => setHovered(n.id)} onMouseLeave={() => setHovered(null)} style={{ cursor: 'pointer' }} data-testid={`twin-node-${n.id}`}>
                <circle cx={n.x} cy={n.y} r={26} fill={c} opacity={0.10}/>
                {isPrimary && <circle cx={n.x} cy={n.y} r={rad + 8} fill="none" stroke="#FF2E63" strokeWidth={1.4} className="pulse-ring"/>}
                {r === 'critical' && !isPrimary && <circle cx={n.x} cy={n.y} r={rad + 6} fill="none" stroke={c} strokeWidth={1} className="pulse-ring"/>}
                {/* CARE ring — outer response state indicator */}
                {action && action !== 'NO_ACTION' && !isPrimary && (
                  <circle cx={n.x} cy={n.y} r={rad + 4} fill="none" stroke={ACTION_COLOR[action]} strokeWidth={1.5} strokeDasharray={action === 'MONITOR' ? '2 3' : action === 'RESTRICT' ? '4 3' : action === 'PROTECT' ? '6 2' : '0'} opacity={0.85}/>
                )}
                <circle cx={n.x} cy={n.y} r={rad} fill="#05070C" stroke={stateColor} strokeWidth={isPrimary ? 2.2 : 1.6}/>
                <circle cx={n.x} cy={n.y} r={4} fill={stateColor}/>
                {/* Action badge */}
                {action && action !== 'NO_ACTION' && !isPrimary && (
                  <g>
                    <rect x={n.x + 10} y={n.y - 22} width={action.length * 5.2 + 8} height={11} rx={2} fill={ACTION_COLOR[action]} opacity={0.16} stroke={ACTION_COLOR[action]} strokeWidth={0.6}/>
                    <text x={n.x + 14} y={n.y - 14} fontSize="7" fontFamily="JetBrains Mono" fill={ACTION_COLOR[action]}>{action}</text>
                  </g>
                )}
                {isPrimary && (
                  <g>
                    <rect x={n.x - 30} y={n.y - 22} width={60} height={11} rx={2} fill="#FF2E63" opacity={0.16} stroke="#FF2E63" strokeWidth={0.6}/>
                    <text x={n.x} y={n.y - 14} fontSize="7" fontFamily="JetBrains Mono" fill="#FF2E63" textAnchor="middle">SUSPECT</text>
                  </g>
                )}
                <text x={n.x} y={n.y + 30} textAnchor="middle" fill="#E9F0FF" fontSize="9.5" fontFamily="JetBrains Mono" opacity={0.72}>{n.label}</text>
                <text x={n.x} y={n.y + 42} textAnchor="middle" fill={stateColor} fontSize="8" fontFamily="JetBrains Mono" opacity={0.55}>{n.ip}</text>
              </g>
            );
          })}
        </svg>
        {hovered && nodeById[hovered] && (
          <div className="absolute top-3 left-3 glass rounded-sm p-3 w-[260px]" data-testid="twin-hover-inspector">
            {(() => {
              const n = nodeById[hovered];
              const Icon = KIND_ICON[n.kind] || Server;
              const r = n.risk as Risk;
              const action = actionByHost[n.id];
              return (
                <>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2"><Icon className="w-4 h-4" style={{ color: RISK_COLOR[r] }}/><span className="font-display text-[12.5px] tracking-wide text-white">{n.label}</span></div>
                    <span className="chip" style={{ borderColor: RISK_COLOR[r], color: RISK_COLOR[r] }}>{r.toUpperCase()}</span>
                  </div>
                  <div className="mt-2 font-mono text-[10.5px] text-white/60 space-y-0.5">
                    <div>ID   {n.id}</div><div>IP   {n.ip}</div><div>TIER {n.tier}</div><div>KIND {n.kind}</div>
                    {action && <div>CARE <span style={{ color: ACTION_COLOR[action] }}>{action}</span></div>}
                    {n.id === primaryId && containmentActive && <div className="text-rose-300">PRIMARY SUSPECT</div>}
                  </div>
                </>
              );
            })()}
          </div>
        )}
        <div className="absolute bottom-3 left-3 glass rounded-sm px-3 py-2 flex items-center gap-4 flex-wrap max-w-[calc(100%-24px)]">
          {(['safe','watch','warn','critical'] as Risk[]).map(r => (
            <div key={r} className="flex items-center gap-1.5 font-mono text-[10px] text-white/60 uppercase"><span className="w-2 h-2 rounded-full" style={{ background: RISK_COLOR[r] }}/>{r}</div>
          ))}
          <div className="pl-3 ml-1 border-l border-white/10 flex items-center gap-3 font-mono text-[10px] text-white/60 uppercase flex-wrap">
            {(['ISOLATE','RESTRICT','MONITOR','PROTECT'] as CareAction[]).map(a => (
              <span key={a} className="flex items-center gap-1"><span className="w-3 h-3 rounded-full border" style={{ borderColor: ACTION_COLOR[a] }}/>{a}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* =========================================================================
   FORECAST RAIL
   ========================================================================= */

function ForecastRail({ state }: { state: FrameState }) {
  const leadStr = fmtLead(state.kpis.lead_time_sec);
  return (
    <div className="corners relative glass rounded-sm p-4" data-testid="forecast-rail">
      <div className="cbr"></div>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2"><TrendingUp className="w-4 h-4 text-violet-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">ATTACK FORECAST</h3></div>
        <span className="chip" style={{ color: '#FFAA00', borderColor: 'rgba(255,170,0,0.35)' }}><AlertTriangle className="w-2.5 h-2.5"/>LEAD {leadStr}</span>
      </div>
      <div className="space-y-1.5">
        {state.stages.map((s) => (
          <div key={s.stage} data-testid={`kc-${s.stage.replace(/\s/g, '-').toLowerCase()}`}>
            <div className="flex items-center justify-between mb-0.5">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: s.color, opacity: s.prob > 0.1 ? 1 : 0.35 }}/>
                <span className="font-mono text-[11px] text-white/75">{s.stage}</span>
                {s.done && <span className="font-mono text-[9px] text-lime-300/80">✓ observed</span>}
              </div>
              <span className="font-mono text-[11px] font-bold" style={{ color: s.color, opacity: s.prob > 0.05 ? 1 : 0.4 }}>{(s.prob * 100).toFixed(0)}%</span>
            </div>
            <div className="h-[6px] bg-white/[0.04] rounded-sm overflow-hidden border border-white/5">
              <div className="h-full" style={{ width: `${s.prob * 100}%`, background: `linear-gradient(90deg, transparent, ${s.color})`, transition: 'width 300ms cubic-bezier(0.16,1,0.3,1)' }}/>
            </div>
          </div>
        ))}
      </div>
      <div className="mt-4 pt-3 border-t border-white/5">
        <div className="font-mono text-[10px] tracking-[0.22em] text-white/45 uppercase mb-2">Predicted Next Targets</div>
        {state.targets.map((t) => (
          <div key={t.host} className="flex items-center justify-between py-1.5" data-testid={`target-${t.host.split(' ')[0]}`}>
            <div className="flex items-center gap-2"><Target className="w-3 h-3" style={{ color: t.color }}/><span className="font-mono text-[11px] text-white/85">{t.host}</span></div>
            <div className="flex items-center gap-2"><span className="font-mono text-[11px] font-bold" style={{ color: t.color, opacity: t.pct > 0.05 ? 1 : 0.3 }}>{(t.pct * 100).toFixed(0)}%</span><span className="font-mono text-[9.5px] text-white/40">{t.eta_min} min</span></div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* =========================================================================
   MITRE
   ========================================================================= */

function MitreMatrix({ state }: { state: FrameState }) {
  const totalTechs = state.mitre.reduce((s, c) => s + c.techniques.length, 0);
  return (
    <div className="corners relative glass rounded-sm p-4" data-testid="mitre-panel">
      <div className="cbr"></div>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2"><ScanEye className="w-4 h-4 text-cyan-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">MITRE ATT&CK MAPPING</h3></div>
        <span className="chip">v13.1 · {state.mitre.length} tactics · {totalTechs} techniques</span>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {state.mitre.map((col) => (
          <div key={col.tactic} className="rounded-sm border border-white/5 bg-white/[0.015] p-2">
            <div className="font-mono text-[9.5px] tracking-[0.16em] text-cyan-300/70 uppercase mb-2">{col.tactic}</div>
            <div className="space-y-1.5">
              {col.techniques.map((t) => (
                <div key={t.id} data-testid={`mitre-${t.id}`} className="rounded-sm border p-1.5"
                  style={{
                    borderColor: !t.active ? 'rgba(255,255,255,0.06)' : t.conf > 0.75 ? 'rgba(255,46,99,0.5)' : t.conf > 0.5 ? 'rgba(255,170,0,0.4)' : 'rgba(0,240,255,0.25)',
                    background: !t.active ? 'rgba(255,255,255,0.008)' : t.conf > 0.75 ? 'rgba(255,46,99,0.06)' : t.conf > 0.5 ? 'rgba(255,170,0,0.05)' : 'rgba(0,240,255,0.04)',
                    opacity: t.active ? 1 : 0.4,
                  }}>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[9.5px] text-white/75">{t.id}</span>
                    <span className="font-mono text-[9.5px] font-bold" style={{ color: !t.active ? '#4A536B' : t.conf > 0.75 ? '#FF6B8B' : t.conf > 0.5 ? '#FFC66B' : '#7DE6F3' }}>{(t.current_conf * 100).toFixed(0)}%</span>
                  </div>
                  <div className="text-[11px] text-white/85 leading-tight">{t.name}</div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* =========================================================================
   XAI
   ========================================================================= */

function XaiPanel({ state }: { state: FrameState }) {
  const active = state.xai.filter(s => s.active);
  const displayed = active.length ? active : state.xai.slice(0, 1).map(s => ({ ...s, weight: 0.01 }));
  const max = Math.max(...displayed.map(s => s.weight), 0.01);
  return (
    <div className="corners relative glass rounded-sm p-4" data-testid="xai-panel">
      <div className="cbr"></div>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2"><BrainCircuit className="w-4 h-4 text-lime-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">EXPLAINABLE AI · EVIDENCE</h3></div>
        <span className="chip"><Eye className="w-2.5 h-2.5"/>SHAP · 80 FEAT</span>
      </div>
      <p className="text-[11.5px] text-white/55 mb-3 leading-relaxed">Contribution of behavioral signals at frame F{String(state.frame).padStart(2,'0')}. Copy evidence to attach to SOC incident.</p>
      <div className="space-y-2">
        {displayed.map((s, i) => {
          const w = (s.weight / max) * 100;
          return (
            <div key={i} data-testid={`xai-signal-${i}`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 min-w-0">
                  {s.dir === 'up' ? <ArrowRight className="w-3 h-3 text-rose-300 rotate-[-45deg]"/> : <ArrowRight className="w-3 h-3 text-lime-300 rotate-[45deg]"/>}
                  <span className="font-mono text-[11px] text-white/85 truncate">{s.name}</span>
                </div>
                <span className="font-mono text-[11px] font-bold text-white/90">{s.weight.toFixed(2)}</span>
              </div>
              <div className="mt-1 h-[6px] bg-white/[0.04] rounded-sm overflow-hidden">
                <div className="h-full" style={{ width: `${w}%`, background: s.dir === 'up' ? 'linear-gradient(90deg, rgba(255,46,99,0.25), #FF2E63)' : 'linear-gradient(90deg, rgba(182,255,61,0.25), #B6FF3D)', transition: 'width 300ms ease' }}/>
              </div>
              <div className="mt-0.5 font-mono text-[9.5px] text-white/40">{s.context}</div>
            </div>
          );
        })}
      </div>
      <button className="btn-tactical mt-4 w-full" data-testid="btn-copy-evidence"><span className="flex items-center justify-center gap-1.5"><ChevronsRight className="w-3.5 h-3.5"/>COPY EVIDENCE TO INCIDENT</span></button>
    </div>
  );
}

/* =========================================================================
   SIMULATION
   ========================================================================= */

function SimulationPanel({ scenario, frame, activeMitigations, setActiveMitigations, sim }: {
  scenario: ScenarioFull; frame: number; activeMitigations: Record<string, boolean>;
  setActiveMitigations: (u: (prev: Record<string, boolean>) => Record<string, boolean>) => void;
  sim: SimResult | null;
}) {
  const baseline = sim?.baseline_risk ?? 0;
  const newRisk = sim?.new_risk ?? baseline;
  const delta = sim?.delta_pct ?? 0;
  return (
    <div className="corners relative glass rounded-sm p-4" data-testid="sim-panel">
      <div className="cbr"></div>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2"><Sparkles className="w-4 h-4 text-violet-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">WHAT-IF DEFENSE SIMULATION</h3></div>
        <span className="chip"><Waves className="w-2.5 h-2.5 text-violet-300"/>SANDBOX · F{String(frame).padStart(2,'0')}</span>
      </div>
      <div className="grid grid-cols-2 gap-3 mb-4">
        <div className="rounded-sm border border-white/5 p-3">
          <div className="font-mono text-[9.5px] tracking-[0.2em] text-white/45 uppercase">Baseline Risk</div>
          <div className="mt-1 font-display text-[26px] font-bold text-rose-300">{(baseline * 100).toFixed(0)}<span className="text-[13px] text-white/40">%</span></div>
          <div className="font-mono text-[10px] text-white/40">peak target · server-computed</div>
        </div>
        <div className="rounded-sm border p-3 relative overflow-hidden" style={{ borderColor: newRisk < 0.35 ? 'rgba(182,255,61,0.45)' : 'rgba(255,170,0,0.4)' }}>
          <div className="font-mono text-[9.5px] tracking-[0.2em] text-white/45 uppercase">After Mitigation</div>
          <div className="mt-1 font-display text-[26px] font-bold" style={{ color: newRisk < 0.35 ? '#B6FF3D' : '#FFC66B' }}>{(newRisk * 100).toFixed(0)}<span className="text-[13px] text-white/40">%</span></div>
          <div className="font-mono text-[10px] text-white/40">Δ {delta}% risk reduction</div>
        </div>
      </div>
      <div className="space-y-1.5">
        {scenario.mitigations.map((m: Mitigation) => {
          const on = !!activeMitigations[m.id]; const Icon = MITIGATION_ICONS[m.icon] || ShieldOff;
          return (
            <button key={m.id} data-testid={`sim-toggle-${m.id}`} onClick={() => setActiveMitigations(a => ({ ...a, [m.id]: !on }))}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-sm border text-left ${on ? 'bg-lime-300/8 border-lime-300/40' : 'border-white/8 hover:border-cyan-400/25 hover:bg-cyan-400/5'}`}>
              <div className="flex items-center gap-2.5 min-w-0">
                <div className={`w-6 h-6 shrink-0 rounded-sm flex items-center justify-center ${on ? 'bg-lime-300/15 text-lime-300' : 'bg-white/5 text-white/60'}`}><Icon className="w-3.5 h-3.5"/></div>
                <span className={`text-[12px] ${on ? 'text-white' : 'text-white/70'}`}>{m.label}</span>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span className={`font-mono text-[10.5px] font-bold ${on ? 'text-lime-300' : 'text-white/40'}`}>{m.delta}%</span>
                <span className={`w-8 h-4 rounded-full relative ${on ? 'bg-lime-300/40' : 'bg-white/10'}`}>
                  <span className="absolute top-0.5 w-3 h-3 rounded-full bg-white" style={{ left: on ? '18px' : '2px', transition: 'left 200ms cubic-bezier(0.16, 1, 0.3, 1)' }}/>
                </span>
              </div>
            </button>
          );
        })}
      </div>
      <button className="btn-tactical primary mt-4 w-full" data-testid="btn-rerun-sim"><span className="flex items-center justify-center gap-1.5"><Zap className="w-3.5 h-3.5"/>RERUN FORECAST WITH DEFENSE</span></button>
    </div>
  );
}

/* =========================================================================
   TERMINAL
   ========================================================================= */

function LiveTerminal({ state }: { state: FrameState }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => { scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' }); }, [state.logs.length]);
  const colorMap: Record<string, string> = { cyan:'#00F0FF', lime:'#B6FF3D', amber:'#FFAA00', rose:'#FF2E63', violet:'#7C6BFF' };
  return (
    <div className="corners relative rounded-sm border border-cyan-400/15 bg-[#070A14]" data-testid="terminal">
      <div className="cbr"></div>
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-white/5">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-lime-300"/>
          <span className="font-display text-[12px] tracking-widest text-white/85">LIVE EVENT STREAM</span>
          <span className="chip"><CircleDot className="w-2 h-2 text-lime-300 blink"/>tail -f twin.jsonl @ F{String(state.frame).padStart(2,'0')}</span>
        </div>
        <div className="flex items-center gap-1.5">
          {['ALL','ANOMALY','ATTACK','FORECAST','DEFEND'].map((f, i) => (
            <button key={f} className={`px-2 py-0.5 font-mono text-[9.5px] tracking-wider rounded-sm border ${i === 0 ? 'bg-cyan-400/10 border-cyan-400/40 text-cyan-200' : 'border-white/8 text-white/50'}`} data-testid={`term-filter-${f.toLowerCase()}`}>{f}</button>
          ))}
        </div>
      </div>
      <div ref={scrollRef} className="h-[240px] overflow-y-auto p-3 font-mono text-[11.5px] leading-relaxed">
        {state.logs.length === 0 && <div className="text-white/30">// awaiting activity...</div>}
        {state.logs.map((l, i) => (
          <div key={i} className="flex gap-3 rise-in">
            <span className="text-white/30 shrink-0">{l.t}</span>
            <span className="shrink-0 font-bold" style={{ color: colorMap[l.color] }}>[{l.tag.padEnd(8)}]</span>
            <span className="text-white/80">{l.text}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* =========================================================================
   ROADMAP + SEGMENTS
   ========================================================================= */

function RoadmapStrip() {
  const items = [
    { phase: 'PHASE 1', title: 'Twin Graph & Hackathon Prototype', status: 'shipped', color: '#B6FF3D' },
    { phase: 'PHASE 2', title: 'Predictive XAI Engine & MITRE Layer', status: 'active', color: '#00F0FF' },
    { phase: 'PHASE 3', title: 'Autonomous Remediation Playbooks', status: 'next', color: '#7C6BFF' },
    { phase: 'PHASE 4', title: 'SOAR Integration · MSSP Multi-tenant', status: 'planned', color: '#FFAA00' },
  ];
  return (
    <div className="corners relative glass rounded-sm p-4" data-testid="roadmap-strip">
      <div className="cbr"></div>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2"><GitBranch className="w-4 h-4 text-cyan-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">COMMERCIALIZATION ROADMAP</h3></div>
        <span className="chip">Predictive Intelligence Layer for Modern SecOps</span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        {items.map((r) => (
          <div key={r.phase} className="rounded-sm p-3 border border-white/5 relative overflow-hidden" data-testid={`roadmap-${r.phase.replace(' ', '-').toLowerCase()}`}>
            <div className="absolute top-0 left-0 h-full w-[3px]" style={{ background: r.color }}/>
            <div className="font-mono text-[10px] tracking-[0.22em] text-white/50">{r.phase}</div>
            <div className="mt-1 text-[13px] text-white/90 font-medium">{r.title}</div>
            <div className="mt-2 flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full" style={{ background: r.color }}/><span className="font-mono text-[10px] tracking-wider uppercase" style={{ color: r.color }}>{r.status}</span></div>
          </div>
        ))}
      </div>
    </div>
  );
}

function TargetSegments() {
  const segs = [
    { icon: Radar,  label: 'SOC Analysts',        detail: 'Prioritise evolving threats · lead time' },
    { icon: Layers, label: 'CISO / Risk Officers',detail: 'Board-ready predictive posture reports' },
    { icon: Zap,    label: 'Red & Blue Teams',    detail: 'Replay attacks · train on twin fidelity' },
    { icon: Globe,  label: 'MSSP Providers',      detail: 'Multi-tenant, prioritised triage' },
  ];
  return (
    <div className="corners relative glass rounded-sm p-4" data-testid="segments-panel">
      <div className="cbr"></div>
      <div className="flex items-center gap-2 mb-3"><User className="w-4 h-4 text-cyan-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">TARGET SEGMENTS</h3></div>
      <div className="grid grid-cols-2 gap-2">
        {segs.map(s => {
          const Icon = s.icon;
          return (
            <div key={s.label} className="rounded-sm border border-white/5 p-3 hover:border-cyan-400/30" data-testid={`segment-${s.label.replace(/\s|\//g, '-').toLowerCase()}`}>
              <Icon className="w-4 h-4 text-cyan-300 mb-2"/>
              <div className="text-[12px] text-white/90 font-medium leading-tight">{s.label}</div>
              <div className="font-mono text-[10px] text-white/45 mt-1">{s.detail}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* =========================================================================
   SECTION HEAD
   ========================================================================= */

function SectionHead({ nav, setNav, frame, scenarioName }: { nav: NavId; setNav: (n: NavId) => void; frame: number; scenarioName?: string; }) {
  const meta: Record<NavId, { title: string; sub: string; icon: typeof Server; tone: string }> = {
    overview: { title: 'Incident Command',       sub: 'Detect · Contain · Analyze · Verify · Report — full autonomous response picture', icon: Radar, tone: '#00F0FF' },
    twin:     { title: 'Digital Twin',           sub: 'Continuously synchronised graph — CARE containment and response state overlaid on hosts and edges', icon: Network, tone: '#00F0FF' },
    forecast: { title: 'Predicted Attack Path',  sub: 'Kill-chain trajectory and likely next targets used for proactive protection', icon: TrendingUp, tone: '#7C6BFF' },
    xai:      { title: 'Decision Explanation',   sub: 'Why hosts were detected, isolated, restricted, monitored or protected — policy-derived reasoning', icon: BrainCircuit, tone: '#B6FF3D' },
    mitre:    { title: 'MITRE ATT&CK',           sub: 'Observed & predicted techniques mapped to v13.1', icon: ScanEye, tone: '#00F0FF' },
    simulate: { title: 'Response Policy Lab',    sub: 'Secondary what-if inspection — estimate simulated effect of manual mitigation combinations', icon: Sparkles, tone: '#7C6BFF' },
    reports:  { title: 'Incident Reports',       sub: 'Auto-generated bundles ready for security-engineer handoff', icon: FileText, tone: '#FFAA00' },
    settings: { title: 'CARE Policy · Settings', sub: 'Autonomous response thresholds, verification window and cycle bounds', icon: Settings, tone: '#FFAA00' },
  };
  const m = meta[nav]; const Icon = m.icon;
  const order: NavId[] = ['overview','twin','forecast','xai','mitre','simulate','reports','settings'];
  const idx = order.indexOf(nav);
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3 rise-in" data-testid="section-head">
      <div>
        <div className="flex items-center gap-2 font-mono text-[10.5px] tracking-[0.3em] text-cyan-300/70 uppercase">
          <Radio className="w-3 h-3 blink text-lime-300"/> {scenarioName || 'Predictive Command Centre'} · F{String(frame).padStart(2,'0')}
        </div>
        <h1 className="mt-2 font-display text-[30px] lg:text-[38px] leading-[1.05] font-bold tracking-tight text-white flex items-center gap-3">
          <Icon className="w-8 h-8" style={{ color: m.tone }}/>{m.title}
        </h1>
        <p className="mt-2 max-w-[720px] text-[13px] text-white/55 leading-relaxed">{m.sub}</p>
      </div>
      <div className="flex items-center gap-2">
        <button className="btn-tactical" onClick={() => setNav(order[Math.max(0, idx - 1)])} data-testid="btn-prev-room"><span className="flex items-center gap-1.5"><ChevronLeft className="w-3.5 h-3.5"/>PREV</span></button>
        <button className="btn-tactical" onClick={() => setNav(order[Math.min(order.length - 1, idx + 1)])} data-testid="btn-next-room"><span className="flex items-center gap-1.5">NEXT<ChevronRight className="w-3.5 h-3.5"/></span></button>
      </div>
    </div>
  );
}

/* =========================================================================
   ROOMS
   ========================================================================= */

function KpiRow({ state }: { state: FrameState }) {
  const leadStr = fmtLead(state.kpis.lead_time_sec);
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-5" data-testid="kpi-row">
      <KpiTile icon={ShieldAlert} label="Active Threat Vectors"  value={String(state.kpis.active_threat_vectors)} tone="rose"   trend={`↑ ${state.kpis.active_threat_vectors} · last 15 min`} testid="kpi-threats"/>
      <KpiTile icon={LineChart}   label="Forecast Confidence"    value={state.kpis.forecast_confidence.toFixed(1)} unit="%" tone="lime"   trend="tw-v3.4.1 · 80 features" testid="kpi-confidence"/>
      <KpiTile icon={Clock}       label="Mean Lead Time"         value={leadStr} tone="cyan"   trend="Δ vs SIEM +8:42" testid="kpi-leadtime"/>
      <KpiTile icon={Network}     label="Twin Nodes Synced"      value={state.kpis.twin_nodes.toLocaleString()} tone="violet" trend={`${state.stages_done}/${state.stages.length} stages observed`} testid="kpi-nodes"/>
    </div>
  );
}

function OverviewRoom({ state, scenario, hovered, setHovered, activeMitigations, setActiveMitigations, sim }: {
  state: FrameState; scenario: ScenarioFull; hovered: string | null; setHovered: (s: string | null) => void;
  activeMitigations: Record<string, boolean>; setActiveMitigations: (u: (p: Record<string, boolean>) => Record<string, boolean>) => void; sim: SimResult | null;
}) {
  return (
    <>
      <IncidentBanner state={state}/>
      <KpiRow state={state}/>
      <EngineerHandoff state={state}/>
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-5">
        <div className="xl:col-span-2 min-w-0"><TwinCanvas state={state} hovered={hovered} setHovered={setHovered}/></div>
        <div className="min-w-0 flex flex-col gap-5">
          <PrimarySuspectCard state={state}/>
          <ForecastRail state={state}/>
        </div>
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-5">
        <div className="xl:col-span-2 min-w-0"><AffectedSystemsPanel state={state}/></div>
        <div className="min-w-0"><XaiPanel state={state}/></div>
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-5">
        <div className="xl:col-span-2 min-w-0"><MitreMatrix state={state}/></div>
        <div className="min-w-0"><TargetSegments/></div>
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-5">
        <div className="xl:col-span-2 min-w-0"><SimulationPanel scenario={scenario} frame={state.frame} activeMitigations={activeMitigations} setActiveMitigations={setActiveMitigations} sim={sim}/></div>
        <div className="min-w-0"><RoadmapStrip/></div>
      </div>
      <div className="grid grid-cols-1 gap-5">
        <div className="min-w-0"><LiveTerminal state={state}/></div>
      </div>
    </>
  );
}

function TwinRoom({ state, hovered, setHovered }: { state: FrameState; hovered: string | null; setHovered: (s: string | null) => void }) {
  return (
    <>
      <IncidentBanner state={state}/>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-5">
        <KpiTile icon={Network}       label="Nodes Tracked"  value={state.kpis.twin_nodes.toLocaleString()} tone="cyan"   trend={`${state.kpis.twin_edges.toLocaleString()} edges`} testid="kpi-nodes-twin"/>
        <KpiTile icon={ShieldAlert}   label="Critical Nodes" value={String(state.kpis.critical_nodes)}      tone="rose"   trend="Crown jewels at risk" testid="kpi-critical-nodes"/>
        <KpiTile icon={AlertTriangle} label="Warn Nodes"     value={String(state.kpis.warn_nodes)}          tone="amber"  trend="Elevated observation" testid="kpi-warn-nodes"/>
        <KpiTile icon={ShieldCheck}   label="Twin Fidelity"  value={state.kpis.twin_fidelity.toFixed(1)}    unit="%" tone="lime" trend="drift < 0.02 rmse" testid="kpi-fidelity"/>
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-5">
        <div className="xl:col-span-2 min-w-0"><TwinCanvas state={state} hovered={hovered} setHovered={setHovered}/></div>
        <div className="min-w-0 flex flex-col gap-5">
          <div className="corners relative glass rounded-sm p-4" data-testid="tier-breakdown">
            <div className="cbr"></div>
            <div className="flex items-center gap-2 mb-3"><Layers className="w-4 h-4 text-cyan-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">TIER BREAKDOWN</h3></div>
            {Array.from(new Set(state.nodes.map(n => n.tier))).map(tier => {
              const list = state.nodes.filter(n => n.tier === tier);
              return (
                <div key={tier} className="py-2 border-b border-white/5 last:border-b-0">
                  <div className="flex items-center justify-between"><span className="font-mono text-[10.5px] tracking-wider text-white/60 uppercase">{tier}</span><span className="font-mono text-[10.5px] text-cyan-300">{list.length}</span></div>
                  <div className="mt-1 flex gap-1">{list.map(n => (<span key={n.id} className="h-1.5 flex-1 rounded-sm" style={{ background: RISK_COLOR[n.risk as Risk] || RISK_COLOR.safe }}/>))}</div>
                </div>
              );
            })}
          </div>
          <PrimarySuspectCard state={state}/>
        </div>
      </div>
      <div className="mb-5"><AffectedSystemsPanel state={state}/></div>
      <LiveTerminal state={state}/>
    </>
  );
}

function ForecastRoom({ state }: { state: FrameState }) {
  return (
    <>
      <IncidentBanner state={state}/>
      <KpiRow state={state}/>
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-5">
        <div className="xl:col-span-2 corners relative glass rounded-sm p-4" data-testid="killchain-timeline">
          <div className="cbr"></div>
          <div className="flex items-center justify-between mb-4"><div className="flex items-center gap-2"><BarChart3 className="w-4 h-4 text-violet-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">PREDICTED ATTACK PATH · KILL-CHAIN TRAJECTORY</h3></div><span className="chip">Frame F{String(state.frame).padStart(2,'0')} · {state.frame_count} total</span></div>
          <div className="space-y-3">
            {state.stages.map(s => (
              <div key={s.stage} className="grid grid-cols-[140px_1fr_60px] gap-3 items-center">
                <div className="font-mono text-[11px] text-white/80">{s.stage}</div>
                <div className="h-3 bg-white/[0.04] rounded-sm relative overflow-hidden border border-white/5">
                  <div className="absolute inset-y-0 rounded-sm" style={{ left: `${(s.activate_at / (state.frame_count - 1)) * 100}%`, width: `${(4 / (state.frame_count - 1)) * 100}%`, background: `${s.color}20` }}/>
                  <div className="absolute inset-y-0 left-0" style={{ width: `${s.prob * 100}%`, background: `linear-gradient(90deg, transparent, ${s.color})`, transition: 'width 300ms cubic-bezier(0.16,1,0.3,1)' }}/>
                  <div className="absolute top-0 bottom-0 w-[2px] bg-white" style={{ left: `${(state.frame / (state.frame_count - 1)) * 100}%`, opacity: 0.7 }}/>
                </div>
                <div className="font-mono text-[11px] font-bold text-right" style={{ color: s.color }}>{(s.prob * 100).toFixed(0)}%</div>
              </div>
            ))}
          </div>
          <div className="mt-4 font-mono text-[10.5px] text-white/45">Predicted next targets can be marked <span style={{ color: ACTION_COLOR.PROTECT }}>PROTECT</span> — critical assets are preserved, suspicious paths restricted, monitoring heightened rather than blindly disconnected.</div>
        </div>
        <div className="min-w-0"><ForecastRail state={state}/></div>
      </div>
      <LiveTerminal state={state}/>
    </>
  );
}

function XaiRoom({ state }: { state: FrameState }) {
  const strongestTarget = state.targets[0]?.host || 'target';
  const eta = state.targets[0]?.eta_min ?? 0;
  const primary = state.incident.primary_suspect;
  const topAction = state.incident.affected_systems.find(h => h.action !== 'NO_ACTION');
  return (
    <>
      <IncidentBanner state={state}/>
      <KpiRow state={state}/>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 mb-5">
        <XaiPanel state={state}/>
        <div className="corners relative glass rounded-sm p-4" data-testid="reasoning-panel">
          <div className="cbr"></div>
          <div className="flex items-center gap-2 mb-3"><BrainCircuit className="w-4 h-4 text-lime-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">DECISION EXPLANATION</h3></div>
          <div className="space-y-3 text-[12.5px] text-white/75 leading-relaxed">
            <p>At <span className="font-mono text-cyan-300">F{String(state.frame).padStart(2,'0')}</span>, temporal model <span className="font-mono text-cyan-300">tw-v3.4.1</span> reports {state.xai.filter(s => s.active).length} active behavioural signals.</p>
            {state.xai.filter(s => s.active).slice(0, 2).map((s, i) => (
              <p key={i} className="pl-3 border-l-2" style={{ borderColor: i === 0 ? 'rgba(182,255,61,0.4)' : 'rgba(255,170,0,0.4)' }}>
                {i === 0 ? 'Primary' : 'Secondary'} contributor: <span className="text-white">{s.name}</span>. {s.context}.
              </p>
            ))}
            {primary && (
              <p className="pl-3 border-l-2" style={{ borderColor: 'rgba(255,46,99,0.4)' }}>
                CARE selected <span className="text-white">{primary.label}</span> as primary suspect (policy-derived conf {(primary.confidence * 100).toFixed(0)}%) — automatic initial containment applied.
              </p>
            )}
            {topAction && (
              <p className="pl-3 border-l-2" style={{ borderColor: `${ACTION_COLOR[topAction.action]}66` }}>
                Highest-impact secondary action: <span className="text-white">{topAction.label}</span> → <span style={{ color: ACTION_COLOR[topAction.action] }}>{topAction.action}</span>. Reason: {topAction.reason}
              </p>
            )}
            <p className="pt-2 border-t border-white/5">Model projects escalation toward <span className="text-white">{strongestTarget}</span> with predicted lead time of <span className="font-mono text-rose-300">{eta} min</span>. Threat confidence values shown above are <span className="text-white">policy-derived</span>, not a separately trained ML probability.</p>
          </div>
        </div>
      </div>
      <LiveTerminal state={state}/>
    </>
  );
}

function SimulateRoom({ state, scenario, hovered, setHovered, activeMitigations, setActiveMitigations, sim }: {
  state: FrameState; scenario: ScenarioFull; hovered: string | null; setHovered: (s: string | null) => void;
  activeMitigations: Record<string, boolean>; setActiveMitigations: (u: (p: Record<string, boolean>) => Record<string, boolean>) => void; sim: SimResult | null;
}) {
  return (
    <>
      <IncidentBanner state={state}/>
      <div className="rounded-sm border p-3 mb-5" style={{ borderColor: 'rgba(255,170,0,0.35)', background: 'rgba(255,170,0,0.05)' }} data-testid="policy-lab-warning">
        <div className="flex items-center gap-2 mb-1"><AlertTriangle className="w-3.5 h-3.5 text-amber-300"/><span className="font-mono text-[10.5px] tracking-[0.24em] text-amber-200 uppercase">Response Policy Lab · secondary use</span></div>
        <div className="text-[12px] text-white/75">The primary containment flow is fully autonomous via CARE. This lab lets analysts inspect <span className="text-white">estimated simulated effect</span> of manual mitigation combinations — not causal proof of real-world outcomes.</div>
      </div>
      <KpiRow state={state}/>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 mb-5">
        <SimulationPanel scenario={scenario} frame={state.frame} activeMitigations={activeMitigations} setActiveMitigations={setActiveMitigations} sim={sim}/>
        <div className="min-w-0"><TwinCanvas state={state} hovered={hovered} setHovered={setHovered} compact/></div>
      </div>
      <LiveTerminal state={state}/>
    </>
  );
}

function ReportsRoom({ state, incidents, onExport, onJumpTo, onRefresh }: {
  state: FrameState; incidents: Incident[]; onExport: (id: string) => void; onJumpTo: (inc: Incident) => void; onRefresh: () => void;
}) {
  return (
    <>
      <IncidentBanner state={state}/>
      <KpiRow state={state}/>
      <EngineerHandoff state={state}/>
      <div className="corners relative glass rounded-sm p-4 mb-5" data-testid="reports-list">
        <div className="cbr"></div>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2"><FileText className="w-4 h-4 text-amber-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">AUTO-GENERATED INCIDENT REPORTS</h3></div>
          <div className="flex items-center gap-2">
            <span className="chip">{incidents.length} bundles</span>
            <button className="btn-tactical !py-1.5 !px-2" onClick={onRefresh} data-testid="btn-refresh-incidents"><RefreshCw className="w-3.5 h-3.5"/></button>
          </div>
        </div>
        {incidents.length === 0 && (
          <div className="py-8 text-center">
            <FileText className="w-8 h-8 text-white/20 mx-auto mb-2"/>
            <div className="text-[13px] text-white/50">No incidents yet.</div>
            <div className="font-mono text-[10.5px] text-white/35 mt-1">CyberWorld will auto-assemble a report once the verification window completes successfully.</div>
          </div>
        )}
        {incidents.map((it) => {
          const auto = !!it.auto;
          const rm = it.snapshot?.response_metrics;
          const life = it.lifecycle;
          return (
            <div key={it.id} className="grid grid-cols-[1fr_auto] gap-4 items-center py-2.5 border-b border-white/5 last:border-b-0" data-testid={`incident-${it.id}`}>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-[13px] text-white/90 truncate">{it.title}</span>
                  {auto && <span className="chip !py-0" style={{ color: '#B6FF3D', borderColor: 'rgba(182,255,61,0.4)' }}>AUTO</span>}
                </div>
                <div className="font-mono text-[10.5px] text-white/40 mt-0.5">
                  {it.id} · {it.scenario_name} · F{String(it.frame).padStart(2,'0')} · {new Date(it.created_at).toLocaleString()}
                </div>
                <div className="mt-1.5 flex items-center gap-2 flex-wrap">
                  {rm ? (
                    <>
                      <span className="chip"><CircleDot className="w-2.5 h-2.5 text-rose-300"/>Peak risk @detect {(rm.peak_risk_at_detection * 100).toFixed(0)}%</span>
                      <span className="chip"><ShieldCheck className="w-2.5 h-2.5 text-lime-300"/>@end {(rm.peak_risk_at_end * 100).toFixed(0)}%</span>
                      <span className="chip"><TrendingUp className="w-2.5 h-2.5 text-cyan-300"/>Cycles {rm.cycles_used}</span>
                      <span className="chip"><Check className="w-2.5 h-2.5 text-lime-300"/>{rm.propagation_stopped ? 'Contained' : 'Escalated'}</span>
                    </>
                  ) : (
                    <span className="chip"><FileText className="w-2.5 h-2.5"/>Manual snapshot</span>
                  )}
                  {life && <span className="chip">Stage: {life.stage}</span>}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button className="btn-tactical !py-1.5" onClick={() => onJumpTo(it)} data-testid={`incident-jump-${it.id}`}><span className="flex items-center gap-1.5"><Eye className="w-3.5 h-3.5"/>OPEN</span></button>
                <button className="btn-tactical !py-1.5" onClick={() => onExport(it.id)} data-testid={`incident-export-${it.id}`}><span className="flex items-center gap-1.5"><Download className="w-3.5 h-3.5"/>EXPORT</span></button>
              </div>
            </div>
          );
        })}
        <div className="mt-3 font-mono text-[10px] text-white/40">Reports are auto-assembled once the verification window closes successfully. JSON export includes the primary suspect, affected systems with CARE decisions, before/after response metrics, and engineer action required.</div>
      </div>
    </>
  );
}

function SettingsRoom({ state, scenario, care, onCarePatch }: { state: FrameState; scenario: ScenarioFull; care: CareSettings | null; onCarePatch: (p: Partial<CareSettings>) => void }) {
  const c = care;
  const row = (label: string, key: keyof CareSettings, min: number, max: number, step: number, unit = '') => c && (
    <div className="py-2 border-b border-white/5 last:border-b-0" data-testid={`care-${String(key)}`}>
      <div className="flex items-center justify-between">
        <span className="text-[12.5px] text-white/85">{label}</span>
        <span className="font-mono text-[11px] text-cyan-300">{(c[key] as number).toFixed(step < 1 ? 2 : 0)}{unit}</span>
      </div>
      <input type="range" min={min} max={max} step={step} value={c[key] as number}
        onChange={(e) => onCarePatch({ [key]: parseFloat(e.target.value) } as Partial<CareSettings>)}
        className="w-full mt-1.5 accent-cyan-400"/>
    </div>
  );
  return (
    <>
      <IncidentBanner state={state}/>
      <KpiRow state={state}/>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <div className="corners relative glass rounded-sm p-4">
          <div className="cbr"></div>
          <div className="flex items-center gap-2 mb-3"><Settings className="w-4 h-4 text-amber-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">CARE POLICY THRESHOLDS</h3></div>
          {row('Detection threshold', 'detection_threshold', 0.4, 0.9, 0.05)}
          {row('Auto-isolate threshold', 'isolate_threshold', 0.6, 1.0, 0.05)}
          {row('Restrict threshold', 'restrict_threshold', 0.4, 0.95, 0.05)}
          {row('Monitor threshold', 'monitor_threshold', 0.2, 0.9, 0.05)}
          {row('Max response cycles', 'max_response_cycles', 1, 5, 1, '×')}
          {row('Verification window (frames)', 'verification_window_frames', 2, 10, 1, ' f')}
          {c && (
            <div className="mt-2 flex items-center justify-between py-2">
              <span className="text-[12.5px] text-white/85">Protect critical assets first</span>
              <button data-testid="care-protect-toggle" onClick={() => onCarePatch({ protect_critical_assets: !c.protect_critical_assets })}
                className={`w-10 h-5 rounded-full relative ${c.protect_critical_assets ? 'bg-lime-300/40' : 'bg-white/10'}`}>
                <span className="absolute top-0.5 w-4 h-4 rounded-full bg-white" style={{ left: c.protect_critical_assets ? '22px' : '2px', transition: 'left 200ms ease' }}/>
              </button>
            </div>
          )}
          <div className="mt-2 font-mono text-[10px] text-white/40">Prototype-level deterministic values — not enterprise policy. Threat confidence is policy-derived.</div>
        </div>
        <div className="corners relative glass rounded-sm p-4">
          <div className="cbr"></div>
          <div className="flex items-center gap-2 mb-3"><BrainCircuit className="w-4 h-4 text-cyan-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">MODEL & SCENARIO</h3></div>
          {[
            { k: 'Model checkpoint',   v: 'tw-v3.4.1' },
            { k: 'Feature schema',     v: 'phase03-v1-sealed · 80 features' },
            { k: 'Temporal window',    v: '5 frames EWMA' },
            { k: 'Threshold',          v: '0.45' },
            { k: 'Explanation method', v: 'SHAP contribution' },
            { k: 'Scenario id',        v: scenario.id },
            { k: 'Scenario seed',      v: '42' },
            { k: 'Total frames',       v: String(state.frame_count) },
            { k: 'Detection frame',    v: `F${state.incident.lifecycle.detection_frame}` },
          ].map((r) => (
            <div key={r.k} className="flex items-center justify-between py-2 border-b border-white/5 last:border-b-0">
              <span className="text-[12.5px] text-white/70">{r.k}</span>
              <span className="font-mono text-[11px] text-cyan-300">{r.v}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

function MitreRoom({ state }: { state: FrameState }) {
  const flat = state.mitre.flatMap(c => c.techniques.map(t => ({ tactic: c.tactic, ...t })));
  return (
    <>
      <KpiRow state={state}/>
      <MitreMatrix state={state}/>
      <div className="corners relative glass rounded-sm p-4 mt-5" data-testid="technique-list">
        <div className="cbr"></div>
        <div className="flex items-center gap-2 mb-3"><ScanEye className="w-4 h-4 text-cyan-300"/><h3 className="font-display text-[13px] tracking-wider text-white/90">TECHNIQUES OBSERVED / PREDICTED</h3></div>
        <div className="grid grid-cols-[70px_140px_1fr_80px_100px] font-mono text-[9.5px] tracking-[0.16em] uppercase text-white/45 border-b border-white/5 pb-2 mb-1">
          <span>ID</span><span>Tactic</span><span>Technique</span><span>Conf</span><span>Status</span>
        </div>
        {flat.map(t => (
          <div key={t.id} className="grid grid-cols-[70px_140px_1fr_80px_100px] py-1.5 border-b border-white/5 last:border-b-0 items-center" style={{ opacity: t.active ? 1 : 0.4 }}>
            <span className="font-mono text-[11px] text-white/85">{t.id}</span>
            <span className="font-mono text-[10.5px] text-cyan-300/80">{t.tactic}</span>
            <span className="text-[12px] text-white/90">{t.name}</span>
            <span className="font-mono text-[11px] font-bold" style={{ color: t.active ? (t.conf > 0.75 ? '#FF6B8B' : t.conf > 0.5 ? '#FFC66B' : '#7DE6F3') : '#4A536B' }}>{(t.current_conf * 100).toFixed(0)}%</span>
            <span className="font-mono text-[10px] tracking-wider uppercase" style={{ color: t.active ? '#B6FF3D' : '#4A536B' }}>{t.active ? 'OBSERVED' : 'AWAITING'}</span>
          </div>
        ))}
      </div>
    </>
  );
}

function SimulateRoom_LEGACY_UNUSED() { return null; }
function ReportsRoom_LEGACY_UNUSED() { return null; }
function SettingsRoom_LEGACY_UNUSED() { return null; }

/* =========================================================================
   TOAST
   ========================================================================= */

function Toast({ msg, tone }: { msg: string | null; tone: 'ok' | 'err' }) {
  if (!msg) return null;
  const color = tone === 'ok' ? '#B6FF3D' : '#FF2E63';
  return (
    <div className="fixed bottom-6 right-6 z-50 glass rounded-sm px-4 py-3 flex items-center gap-3 rise-in" data-testid="toast" style={{ borderColor: color, boxShadow: `0 0 24px -4px ${color}88` }}>
      {tone === 'ok' ? <Check className="w-4 h-4" style={{ color }}/> : <AlertTriangle className="w-4 h-4" style={{ color }}/>}
      <span className="text-[12.5px] text-white/90">{msg}</span>
    </div>
  );
}

/* =========================================================================
   APP
   ========================================================================= */

function App() {
  const [nav, setNav] = useState<NavId>('overview');
  const [hovered, setHovered] = useState<string | null>(null);

  // remote data
  const [scenarios, setScenarios] = useState<ScenarioMeta[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [scenarioId, setScenarioId] = useState<string | null>(null);
  const [tenantId, setTenantId] = useState<string | null>(null);
  const [scenario, setScenario] = useState<ScenarioFull | null>(null);
  const [frameState, setFrameState] = useState<FrameState | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [care, setCare] = useState<CareSettings | null>(null);

  const [frame, setFrame] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [activeMitigations, setActiveMitigations] = useState<Record<string, boolean>>({});
  const [sim, setSim] = useState<SimResult | null>(null);

  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState<{ msg: string; tone: 'ok' | 'err' } | null>(null);

  const flash = useCallback((msg: string, tone: 'ok' | 'err' = 'ok') => {
    setToast({ msg, tone });
    setTimeout(() => setToast(null), 3200);
  }, []);

  // boot
  useEffect(() => {
    (async () => {
      try {
        const [sc, tn, cs] = await Promise.all([api.listScenarios(), api.listTenants(), api.getCareSettings()]);
        setScenarios(sc); setTenants(tn); setCare(cs);
        if (sc.length > 0) setScenarioId(sc.find(s => s.id === 'sc-ransom-ω-7742')?.id || sc[0].id);
        if (tn.length > 0) setTenantId(tn[0].id);
      } catch (e) {
        flash(`Failed to reach backend: ${(e as Error).message}`, 'err');
      } finally {
        setLoading(false);
      }
    })();
  }, [flash]);

  // load scenario detail
  useEffect(() => {
    if (!scenarioId) return;
    (async () => {
      try {
        const full = await api.getScenario(scenarioId);
        setScenario(full);
        // reset mitigations for new scenario, default pick highest-impact
        const top = [...full.mitigations].sort((a,b) => a.delta - b.delta)[0];
        setActiveMitigations(top ? { [top.id]: true } : {});
        setFrame(0); // start from Baseline; user presses Play (no auto-play per plan)
      } catch (e) {
        flash(`Failed to load scenario: ${(e as Error).message}`, 'err');
      }
    })();
  }, [scenarioId, flash]);

  // fetch frame state
  useEffect(() => {
    if (!scenarioId) return;
    let alive = true;
    (async () => {
      try {
        const st = await api.getFrame(scenarioId, frame);
        if (alive) setFrameState(st);
      } catch (e) {
        if (alive) flash(`Frame fetch failed: ${(e as Error).message}`, 'err');
      }
    })();
    return () => { alive = false; };
  }, [scenarioId, frame, flash]);

  // simulation recompute on toggles / frame / scenario change
  useEffect(() => {
    if (!scenarioId) return;
    const active = Object.keys(activeMitigations).filter(k => activeMitigations[k]);
    let alive = true;
    (async () => {
      try {
        const r = await api.simulate(scenarioId, frame, active);
        if (alive) setSim(r);
      } catch (_) { /* silent */ }
    })();
    return () => { alive = false; };
  }, [scenarioId, frame, activeMitigations]);

  const refreshIncidents = useCallback(async () => {
    try {
      // fetch all — auto reports are tenant-less by design
      const list = await api.listIncidents();
      setIncidents(list);
    } catch (_) { /* silent */ }
  }, []);
  useEffect(() => { refreshIncidents(); }, [refreshIncidents, frameState?.incident.lifecycle.stage]);

  // auto-stop scrubber
  useEffect(() => {
    if (!frameState) return;
    if (frame >= frameState.frame_count - 1 && playing) setPlaying(false);
  }, [frame, playing, frameState]);

  const exportIncident = useCallback((id: string) => {
    const inc = incidents.find(i => i.id === id);
    if (!inc) return;
    const blob = new Blob([JSON.stringify(inc, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${inc.id}.json`; a.click();
    URL.revokeObjectURL(url);
    flash(`Exported ${inc.id}.json`);
  }, [incidents, flash]);

  const jumpToIncident = useCallback((inc: Incident) => {
    if (inc.scenario_id !== scenarioId) setScenarioId(inc.scenario_id);
    setFrame(inc.frame);
    if (inc.mitigation_ids && inc.mitigation_ids.length) {
      setActiveMitigations(Object.fromEntries(inc.mitigation_ids.map(id => [id, true])));
    }
    setNav('overview');
    flash(`Loaded ${inc.id}`);
  }, [scenarioId, flash]);

  const patchCare = useCallback(async (patch: Partial<CareSettings>) => {
    try {
      const updated = await api.putCareSettings(patch);
      setCare(updated);
      // trigger frame refetch to reflect new thresholds
      if (scenarioId) {
        const st = await api.getFrame(scenarioId, frame);
        setFrameState(st);
      }
      await refreshIncidents();
    } catch (e) {
      flash(`CARE update failed: ${(e as Error).message}`, 'err');
    }
  }, [scenarioId, frame, refreshIncidents, flash]);

  if (loading) {
    return (
      <div className="grain bg-radial min-h-screen text-white flex items-center justify-center" data-testid="boot-loader">
        <div className="text-center">
          <Loader2 className="w-8 h-8 text-cyan-300 animate-spin mx-auto"/>
          <div className="mt-3 font-mono text-[11px] tracking-[0.24em] text-cyan-300/70 uppercase">Booting Predictive Command Centre…</div>
        </div>
      </div>
    );
  }

  if (!scenario || !frameState) {
    return (
      <div className="grain bg-radial min-h-screen text-white flex items-center justify-center">
        <div className="text-center">
          <AlertTriangle className="w-8 h-8 text-rose-300 mx-auto"/>
          <div className="mt-3 font-mono text-[12px] text-rose-300">No scenario loaded — check backend /api/health</div>
        </div>
      </div>
    );
  }

  const currentTenant = tenants.find(t => t.id === tenantId);

  return (
    <div className="grain bg-radial min-h-screen text-white">
      <TopBar
        conf={frameState.kpis.forecast_confidence}
        scenarios={scenarios} scenarioId={scenarioId} onScenario={setScenarioId}
        tenants={tenants} tenantId={tenantId} onTenant={setTenantId}
        lifecycleStage={frameState.incident.lifecycle.stage}
      />
      <div className="flex">
        <NavRail current={nav} setCurrent={setNav} tenant={currentTenant} operator={currentTenant?.operator}/>
        <main className="flex-1 min-w-0 p-4 lg:p-6 xl:p-8">
          <SectionHead nav={nav} setNav={setNav} frame={frame} scenarioName={scenario.name}/>
          <ReplayScrubber frame={frame} setFrame={setFrame} playing={playing} setPlaying={setPlaying} speed={speed} setSpeed={setSpeed} frameCount={frameState.frame_count}/>

          <div key={nav} className="rise-in">
            {nav === 'overview' && <OverviewRoom state={frameState} scenario={scenario} hovered={hovered} setHovered={setHovered} activeMitigations={activeMitigations} setActiveMitigations={setActiveMitigations} sim={sim}/>}
            {nav === 'twin'     && <TwinRoom     state={frameState} hovered={hovered} setHovered={setHovered}/>}
            {nav === 'forecast' && <ForecastRoom state={frameState}/>}
            {nav === 'xai'      && <XaiRoom      state={frameState}/>}
            {nav === 'mitre'    && <MitreRoom    state={frameState}/>}
            {nav === 'simulate' && <SimulateRoom state={frameState} scenario={scenario} hovered={hovered} setHovered={setHovered} activeMitigations={activeMitigations} setActiveMitigations={setActiveMitigations} sim={sim}/>}
            {nav === 'reports'  && <ReportsRoom  state={frameState} incidents={incidents} onExport={exportIncident} onJumpTo={jumpToIncident} onRefresh={refreshIncidents}/>}
            {nav === 'settings' && <SettingsRoom state={frameState} scenario={scenario} care={care} onCarePatch={patchCare}/>}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-4 mt-8 border-t border-white/5 text-[11px] text-white/40 font-mono" data-testid="footer-strip">
            <div>CyberWorld AI · Autonomous Cyber-Containment Prototype · Twin v3.4.1</div>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1.5"><CircleDot className="w-2 h-2 text-rose-300"/>Detect</span>
              <span className="flex items-center gap-1.5"><CircleDot className="w-2 h-2 text-amber-300"/>Contain</span>
              <span className="flex items-center gap-1.5"><CircleDot className="w-2 h-2 text-cyan-300"/>Analyze</span>
              <span className="flex items-center gap-1.5"><CircleDot className="w-2 h-2 text-violet-300"/>Verify</span>
              <span className="flex items-center gap-1.5"><CircleDot className="w-2 h-2 text-lime-300"/>Report</span>
            </div>
            <div>API: /api · scenario {scenario.id} · seed 42</div>
          </div>
        </main>
      </div>

      <Toast msg={toast?.msg || null} tone={toast?.tone || 'ok'}/>
    </div>
  );
}

export default App;

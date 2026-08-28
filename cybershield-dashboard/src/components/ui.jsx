import { ShieldAlert, AlertTriangle, HelpCircle, ShieldCheck, Loader2 } from 'lucide-react';

export const LEVEL_META = {
  MALICIOUS: {
    label: 'Malicious',
    priority: 'P1',
    icon: ShieldAlert,
    badgeCls: 'bg-red-500/10 text-red-400 border-red-500/30 shadow-rose-glow',
    dotCls: 'bg-red-500',
    barCls: 'bg-red-500',
    color: '#f43f5e',
  },
  HIGH_RISK: {
    label: 'High Risk',
    priority: 'P2',
    icon: AlertTriangle,
    badgeCls: 'bg-orange-500/10 text-orange-400 border-orange-500/30 shadow-amber-glow',
    dotCls: 'bg-orange-500',
    barCls: 'bg-orange-500',
    color: '#f97316',
  },
  SUSPICIOUS: {
    label: 'Suspicious',
    priority: 'P3',
    icon: HelpCircle,
    badgeCls: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
    dotCls: 'bg-yellow-400',
    barCls: 'bg-yellow-500',
    color: '#eab308',
  },
  SAFE: {
    label: 'Clean / Safe',
    priority: 'P4',
    icon: ShieldCheck,
    badgeCls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shadow-emerald-glow',
    dotCls: 'bg-emerald-500',
    barCls: 'bg-emerald-500',
    color: '#10b981',
  },
};

export function RiskBadge({ level, showPriority = true }) {
  const m = LEVEL_META[level] || LEVEL_META.SAFE;
  const Icon = m.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-semibold backdrop-blur-md transition-all ${m.badgeCls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${m.dotCls} animate-cyber-pulse`} />
      {showPriority && <span className="font-mono text-[11px] opacity-80">{m.priority}</span>}
      <Icon className="h-3.5 w-3.5" />
      <span>{m.label}</span>
    </span>
  );
}

export function ScoreRing({ score, size = 'md' }) {
  const color = score >= 75 ? '#f43f5e' : score >= 50 ? '#f97316' : score >= 25 ? '#eab308' : '#10b981';
  const dim = size === 'lg' ? 'h-20 w-20' : size === 'sm' ? 'h-10 w-10' : 'h-16 w-16';
  const strokeWidth = size === 'lg' ? 3.5 : 3;
  const textCls = size === 'lg' ? 'text-xl' : size === 'sm' ? 'text-xs' : 'text-base';

  return (
    <div className={`relative ${dim} shrink-0 flex items-center justify-center`}>
      <svg viewBox="0 0 36 36" className="h-full w-full -rotate-90 transform filter drop-shadow">
        <circle cx="18" cy="18" r="15.5" fill="none" stroke="#1e2638" strokeWidth={strokeWidth} />
        <circle
          cx="18"
          cy="18"
          r="15.5"
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={`${(score / 100) * 97.4} 97.4`}
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`font-mono font-bold tracking-tight text-white ${textCls}`}>{score}</span>
        {size === 'lg' && <span className="text-[9px] uppercase tracking-wider text-slate-400 font-medium">Risk</span>}
      </div>
    </div>
  );
}

export function Card({ title, children, right, icon: Icon, className = '' }) {
  return (
    <div className={`glass-card rounded-2xl p-5 ${className}`}>
      {(title || right || Icon) && (
        <div className="mb-4 flex items-center justify-between border-b border-cyber-border/60 pb-3">
          <div className="flex items-center gap-2.5">
            {Icon && <Icon className="h-4 w-4 text-cyber-accent" />}
            {title && <h3 className="text-sm font-bold tracking-wide uppercase text-slate-200">{title}</h3>}
          </div>
          {right}
        </div>
      )}
      {children}
    </div>
  );
}

export function StatWidget({ label, value, tone, subtext, icon: Icon }) {
  return (
    <div className="glass-card relative overflow-hidden rounded-2xl p-5">
      <div className="flex items-start justify-between">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">{label}</div>
          <div className={`mt-2 font-mono text-3xl font-bold tracking-tight ${tone || 'text-white'}`}>
            {value ?? 0}
          </div>
          {subtext && <div className="mt-1 text-xs text-slate-400 font-medium">{subtext}</div>}
        </div>
        {Icon && (
          <div className="rounded-xl border border-cyber-border bg-cyber-dark/60 p-2.5 text-cyber-accent shadow-inner">
            <Icon className="h-5 w-5" />
          </div>
        )}
      </div>
      {/* Decorative subtle ambient glow */}
      <div className="absolute -bottom-10 -right-10 h-24 w-24 rounded-full bg-cyber-accent/5 blur-xl pointer-events-none" />
    </div>
  );
}

export function BarList({ items = [], max }) {
  const top = max || Math.max(1, ...items.map((i) => i.count ?? i.value ?? 0));
  return (
    <div className="space-y-3">
      {items.length === 0 && <p className="py-4 text-center text-xs text-slate-500">No signals recorded yet.</p>}
      {items.map((i, idx) => {
        const v = i.count ?? i.value ?? 0;
        const pct = Math.round((v / top) * 100);
        return (
          <div key={idx} className="group relative flex flex-col gap-1 rounded-lg p-1.5 transition-colors hover:bg-cyber-border/30">
            <div className="flex items-center justify-between text-xs">
              <span className="truncate font-medium text-slate-300 group-hover:text-cyber-accent transition-colors" title={i.label}>
                {i.label}
              </span>
              <span className="font-mono font-semibold text-slate-200">{v}</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-cyber-border/60">
              <div
                className="h-full rounded-full bg-gradient-to-r from-cyber-accent to-cyber-indigo transition-all duration-500"
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function Spinner({ className = 'h-5 w-5' }) {
  return <Loader2 className={`animate-spin text-cyber-accent ${className}`} />;
}

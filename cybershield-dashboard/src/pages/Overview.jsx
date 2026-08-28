import { useEffect, useState } from 'react';
import { ShieldAlert, Activity, FileText, AlertOctagon, TrendingUp, Layers, Cpu } from 'lucide-react';
import { api } from '../api.js';
import { Card, StatWidget, BarList, Spinner, LEVEL_META } from '../components/ui.jsx';

export default function Overview() {
  const [stats, setStats] = useState(null);
  const [trends, setTrends] = useState(null);
  const [err, setErr] = useState('');

  useEffect(() => {
    Promise.all([api.stats(), api.trends()])
      .then(([s, t]) => {
        setStats(s);
        setTrends(t);
      })
      .catch((e) => setErr(e.message));
  }, []);

  if (err) {
    return (
      <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-6 text-red-400 flex items-center gap-3">
        <AlertOctagon className="h-6 w-6 shrink-0" />
        <div>
          <h4 className="font-bold">Error loading overview data</h4>
          <p className="text-sm">{err}</p>
        </div>
      </div>
    );
  }

  if (!stats || !trends) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-3 text-slate-400">
        <Spinner className="h-8 w-8" />
        <span className="font-mono text-xs uppercase tracking-widest text-slate-500">
          Gathering Threat Intelligence…
        </span>
      </div>
    );
  }

  const lvl = stats.scansByRiskLevel || {};
  const perDay = Object.entries(trends.perDay || {}).map(([label, count]) => ({ label, count }));
  const perType = Object.entries(stats.scansByContentType || {}).map(([label, count]) => ({ label, count }));

  return (
    <div className="space-y-8">
      {/* Top Welcome & Quick Header */}
      <div className="flex flex-col justify-between gap-4 md:flex-row md:items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Security Command Overview</h1>
          <p className="mt-1 text-xs text-slate-400">
            Real-time threat metrics, cold archive signals, and community report activity.
          </p>
        </div>
        <div className="flex items-center gap-2 rounded-xl border border-cyber-border bg-cyber-card/60 px-3.5 py-2 text-xs font-mono text-slate-300">
          <Cpu className="h-4 w-4 text-cyber-accent" />
          <span>Hot DB Engine Active</span>
        </div>
      </div>

      {/* Hero Stat Grid */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <StatWidget
          label="Total Scans Processed"
          value={stats.totalScans}
          icon={Activity}
          subtext="Full pipeline audit log"
        />
        <StatWidget
          label="Scans (Last 7 Days)"
          value={stats.scansLast7Days}
          tone="text-cyber-accent"
          icon={TrendingUp}
          subtext="Recent threat traffic"
        />
        <StatWidget
          label="Pending Reports"
          value={stats.reportsPending}
          tone="text-yellow-400"
          icon={FileText}
          subtext="Awaiting admin review"
        />
        <StatWidget
          label="Confirmed Threats"
          value={stats.reportsConfirmed}
          tone="text-red-400"
          icon={ShieldAlert}
          subtext="Added to community blocklist"
        />
      </div>

      {/* Analytics Grid Row 1 */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Risk Classification Breakdown" icon={ShieldAlert}>
          <div className="space-y-3 pt-2">
            {['MALICIOUS', 'HIGH_RISK', 'SUSPICIOUS', 'SAFE'].map((k) => {
              const total = Object.values(lvl).reduce((a, b) => a + b, 0) || 1;
              const v = lvl[k] || 0;
              const m = LEVEL_META[k];
              const pct = Math.round((v / total) * 100);
              return (
                <div key={k} className="group rounded-xl border border-cyber-border/40 bg-cyber-dark/40 p-3">
                  <div className="flex items-center justify-between text-xs mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`h-2 w-2 rounded-full ${m.dotCls}`} />
                      <span className="font-mono text-slate-400 text-[11px]">{m.priority}</span>
                      <span className="font-semibold text-slate-200">{m.label}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-slate-400">{pct}%</span>
                      <span className="font-mono font-bold text-slate-200">{v}</span>
                    </div>
                  </div>
                  <div className="h-2 w-full overflow-hidden rounded-full bg-cyber-border/60">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${m.barCls}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </Card>

        <Card title="Content Type Distribution" icon={Layers}>
          <div className="pt-2">
            <BarList items={perType} />
          </div>
        </Card>
      </div>

      {/* Analytics Grid Row 2 */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Scan Volume per Day (Cold Archive)" icon={Activity}>
          <div className="pt-2">
            <BarList items={perDay} />
          </div>
        </Card>

        <Card title="Top Detected Signals" icon={AlertOctagon}>
          <div className="pt-2">
            <BarList items={(trends.topSignals || []).map((s) => ({ label: s.label, count: s.count }))} />
          </div>
        </Card>
      </div>

      {/* Top Scam Categories */}
      <Card title="Top Identified Scam Categories" icon={FileText}>
        <div className="pt-2">
          <BarList items={(trends.topCategories || []).map((c) => ({ label: c.label, count: c.count }))} />
        </div>
      </Card>
    </div>
  );
}

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, Activity, FileText, AlertOctagon, TrendingUp, Layers, ArrowUpRight } from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { api } from '../api.js';
import { Card, StatWidget, BarList, Spinner } from '../components/ui.jsx';
import ParticleOrb from '../components/ParticleOrb.jsx';

const PIE_COLORS = ['#63e31a', '#2fbf71', '#a3e635', '#ff5c66', '#ff9f43', '#5f7566'];

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0];
    return (
      <div className="rounded-xl border border-cyber-border bg-slate-950/95 p-3 text-xs shadow-2xl backdrop-blur-xl">
        <div className="flex items-center gap-2 font-bold text-slate-100">
          <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: data.color || data.payload.fill }} />
          <span>{data.name}</span>
        </div>
        <div className="mt-1 font-mono font-semibold text-cyber-accent">Count: {data.value}</div>
      </div>
    );
  }
  return null;
};

function Hero() {
  return (
    <section className="relative mb-14 flex min-h-[560px] items-center md:min-h-[620px]">
      <ParticleOrb className="absolute inset-0 h-full w-full" />
      <div className="relative z-10 grid w-full items-center gap-10 md:grid-cols-[1.3fr_minmax(160px,280px)_1fr]">
        <div>
          <div className="label-mono mb-6">[ Threat overview ]</div>
          <h1 className="display text-[clamp(2.2rem,4.3vw,4rem)]">
            Stopping scams
            <br />
            before they land
          </h1>
          <Link to="/analyze" className="pill-cta mt-9">
            Analyze now
            <span className="dot">
              <ArrowUpRight className="h-4 w-4" />
            </span>
          </Link>
        </div>
        <div className="hidden md:block" />
        <div className="md:pl-6">
          <h1 className="display text-[clamp(2.2rem,4.3vw,4rem)] md:text-right">
            in real
            <br />
            time.
          </h1>
          <p className="mt-6 max-w-[250px] text-xs leading-relaxed text-slate-400 md:ml-auto md:text-right">
            Live scans, community reports and threat trends from every Secure Me app, browser extension and console.
          </p>
        </div>
      </div>
    </section>
  );
}

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
      <>
      <Hero />
      <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-6 text-red-400 flex items-center gap-3">
        <AlertOctagon className="h-6 w-6 shrink-0" />
        <div>
          <h4 className="font-bold">Error loading overview data</h4>
          <p className="text-sm">{err}</p>
        </div>
      </div>
      </>
    );
  }

  if (!stats || !trends) {
    return (
      <>
      <Hero />
      <div className="flex h-64 flex-col items-center justify-center gap-3 text-slate-400">
        <Spinner className="h-8 w-8" />
        <span className="font-mono text-xs uppercase tracking-widest text-slate-500">
          Gathering Threat Intelligence…
        </span>
      </div>
      </>
    );
  }

  const lvl = stats.scansByRiskLevel || {};
  const perDay = Object.entries(trends.perDay || {}).map(([label, count]) => ({ label, count }));
  const perType = Object.entries(stats.scansByContentType || {}).map(([label, count]) => ({ label, count }));

  // Pie chart formatted data
  const riskPieData = [
    { name: 'Malicious', value: lvl.MALICIOUS || 0, fill: '#ff5c66' },
    { name: 'High Risk', value: lvl.HIGH_RISK || 0, fill: '#ff9f43' },
    { name: 'Suspicious', value: lvl.SUSPICIOUS || 0, fill: '#f5d547' },
    { name: 'Clean / Safe', value: lvl.SAFE || 0, fill: '#63e31a' },
  ].filter(d => d.value > 0);

  const typePieData = perType.map((item, idx) => ({
    name: item.label,
    value: item.count,
    fill: PIE_COLORS[idx % PIE_COLORS.length],
  }));

  return (
    <div className="space-y-10">
      <Hero />

      <div>
        <div className="label-mono mb-3">[ 01 ] Live metrics</div>
        <h2 className="display text-[clamp(1.8rem,3.4vw,2.8rem)]">
          What is happening <span className="dim">right now</span>
        </h2>
      </div>

      {/* Hero Stat Grid */}
      <div className="tile-cycle grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
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

      {/* Analytics Grid Row 1: Interactive Pie Charts */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Risk Classification Breakdown" icon={ShieldAlert}>
          <div className="h-64 w-full pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskPieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={90}
                  paddingAngle={4}
                  dataKey="value"
                  nameKey="name"
                  stroke="none"
                  isAnimationActive={true}
                >
                  {riskPieData.map((entry, index) => (
                    <Cell key={`risk-cell-${index}`} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  formatter={(value) => <span className="text-xs font-semibold text-slate-300">{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card title="Content Type Distribution" icon={Layers}>
          <div className="h-64 w-full pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={typePieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={88}
                  paddingAngle={3}
                  dataKey="value"
                  nameKey="name"
                  stroke="none"
                  isAnimationActive={true}
                >
                  {typePieData.map((entry, index) => (
                    <Cell key={`type-cell-${index}`} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  formatter={(value) => <span className="text-xs font-semibold text-slate-300">{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
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

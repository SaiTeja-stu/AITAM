import { useEffect, useState } from 'react';
import { GraduationCap, BookOpen, AlertOctagon, CheckCircle2, ShieldCheck } from 'lucide-react';
import { api } from '../api.js';
import { Spinner } from '../components/ui.jsx';

export default function Education() {
  const [mods, setMods] = useState(null);
  const [err, setErr] = useState('');

  useEffect(() => {
    api.education().then(setMods).catch((e) => setErr(e.message));
  }, []);

  if (err) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-xs text-red-400 flex items-center gap-2">
        <AlertOctagon className="h-4 w-4 shrink-0" />
        <span>{err}</span>
      </div>
    );
  }

  if (!mods) {
    return (
      <div className="flex h-48 items-center justify-center gap-2 text-slate-400">
        <Spinner /> <span className="font-mono text-xs">Loading awareness modules…</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <GraduationCap className="h-6 w-6 text-cyber-accent" /> Security Awareness & Training Modules
        </h1>
        <p className="mt-1 text-xs text-slate-400">
          Educational content served live via <code className="font-mono text-cyber-accent">/api/v1/education/modules</code> — synchronized with thin clients (Android App & Chrome Extension).
        </p>
      </div>

      {/* Grid of Module Cards */}
      <div className="grid gap-6 md:grid-cols-2">
        {mods.map((m) => (
          <div
            key={m.id}
            className="glass-card rounded-2xl p-6 border border-cyber-border/80 flex flex-col justify-between space-y-4 transition-all hover:border-cyber-accent/40 hover:shadow-cyber-glow"
          >
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="rounded-lg border border-cyber-accent/30 bg-cyber-accent/10 px-3 py-1 font-mono text-[11px] font-bold text-cyber-accent uppercase tracking-wider">
                  {m.category}
                </span>
                <span className="flex items-center gap-1 font-mono text-[11px] text-slate-400">
                  <BookOpen className="h-3.5 w-3.5 text-cyber-accent" /> Module #{m.id}
                </span>
              </div>

              <h3 className="text-base font-bold text-white tracking-wide">{m.title}</h3>
              <p className="text-xs text-slate-300 leading-relaxed">{m.summary}</p>

              {/* Key Points */}
              {m.keyPoints && m.keyPoints.length > 0 && (
                <div className="rounded-xl border border-cyber-border/60 bg-cyber-dark/60 p-3.5 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-bold text-emerald-400">
                    <ShieldCheck className="h-4 w-4" /> Defense Best Practices
                  </div>
                  <ul className="space-y-1.5 text-xs text-slate-300">
                    {m.keyPoints.map((k, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-400 mt-0.5" />
                        <span>{k}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Red Flags */}
              {m.redFlags && m.redFlags.length > 0 && (
                <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3.5 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-bold text-red-400">
                    <AlertOctagon className="h-4 w-4" /> Threat Red Flags
                  </div>
                  <ul className="space-y-1.5 text-xs text-slate-300">
                    {m.redFlags.map((k, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-red-400" />
                        <span>{k}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

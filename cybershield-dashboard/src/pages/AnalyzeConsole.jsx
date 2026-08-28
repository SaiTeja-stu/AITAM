import { useState } from 'react';
import { SearchCode, Play, Trash2, ShieldAlert, CreditCard, Sparkles, CheckCircle2, AlertOctagon } from 'lucide-react';
import { api } from '../api.js';
import { RiskBadge, ScoreRing, Card, Spinner } from '../components/ui.jsx';

const TYPES = ['URL', 'EMAIL', 'SMS', 'QR', 'WEBPAGE', 'SOCIAL'];

const SAMPLES = {
  SMS: 'URGENT: your SBI account is blocked. Verify KYC at http://sbi-netbanking-update.in and share the OTP now',
  QR: 'upi://collect?pa=random123@okhdfcbank&pn=Amazon%20Refund&am=4999&tn=refund',
  URL: 'https://paypa1-verify.com/login',
  EMAIL: 'Dear Customer, Your bank account requires urgent verification. Click http://bank-update-verify.com to log in.',
  WEBPAGE: '<html><head><title>Verify Bank Account</title></head><body><form action="http://phishing-site.xyz/steal"><input name="pass" type="password"/></form></body></html>',
  SOCIAL: 'Hey bro check out this secret crypto giveaway link: http://bit.ly/claim-free-eth-bonus now!!',
};

const SEV_META = {
  CRITICAL: { cls: 'bg-red-500/10 text-red-400 border-red-500/30', label: 'CRITICAL' },
  HIGH: { cls: 'bg-orange-500/10 text-orange-400 border-orange-500/30', label: 'HIGH' },
  MEDIUM: { cls: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30', label: 'MEDIUM' },
  LOW: { cls: 'bg-slate-500/10 text-slate-300 border-slate-500/30', label: 'LOW' },
  TRUST: { cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30', label: 'TRUST' },
};

export default function AnalyzeConsole() {
  const [type, setType] = useState('SMS');
  const [content, setContent] = useState(SAMPLES.SMS);
  const [res, setRes] = useState(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  async function run() {
    if (!content.trim()) return;
    setBusy(true);
    setErr('');
    setRes(null);
    try {
      setRes(await api.analyze({ type, content, source: 'dashboard' }));
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <SearchCode className="h-6 w-6 text-cyber-accent" /> Cyber Threat Inspector Console
        </h1>
        <p className="mt-1 text-xs text-slate-400">
          Run deep multi-policy security scans across raw URLs, SMS strings, UPI QR codes, Emails, or Webpage HTML.
        </p>
      </div>

      <div className="grid gap-8 lg:grid-cols-12">
        {/* Left Column: Input & Controls */}
        <div className="space-y-5 lg:col-span-5">
          <div className="glass-card rounded-2xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Payload Type</span>
              <button
                onClick={() => setContent('')}
                className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-red-400 transition-colors"
              >
                <Trash2 className="h-3 w-3" /> Clear Console
              </button>
            </div>

            {/* Type selector tabs */}
            <div className="grid grid-cols-3 gap-1.5 rounded-xl border border-cyber-border bg-cyber-dark/80 p-1.5">
              {TYPES.map((t) => (
                <button
                  key={t}
                  onClick={() => {
                    setType(t);
                    if (SAMPLES[t]) setContent(SAMPLES[t]);
                  }}
                  className={`rounded-lg px-2 py-1.5 text-xs font-semibold transition-all ${
                    type === t
                      ? 'bg-cyber-accent/20 text-cyber-accent border border-cyber-accent/40 shadow-cyber-glow'
                      : 'text-slate-400 hover:bg-cyber-border/40 hover:text-slate-200'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>

            {/* Content Textarea */}
            <div>
              <div className="mb-2 flex items-center justify-between text-xs text-slate-400">
                <span>Input Payload Buffer</span>
                <span className="font-mono">{content.length} chars</span>
              </div>
              <textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                rows={10}
                className="w-full rounded-xl border border-cyber-border bg-cyber-dark p-3.5 font-mono text-xs text-slate-200 placeholder-slate-600 outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent"
                placeholder="Paste URL, SMS, email payload, UPI QR string, or raw HTML..."
              />
            </div>

            {/* Run Button */}
            <button
              onClick={run}
              disabled={busy || !content.trim()}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyber-accent to-cyber-indigo py-3 text-sm font-bold text-slate-950 transition-all hover:opacity-90 disabled:opacity-50 shadow-cyber-glow"
            >
              {busy ? <Spinner className="h-4 w-4 text-slate-950" /> : <Play className="h-4 w-4 fill-slate-950" />}
              <span>{busy ? 'Running Security Engine…' : 'Execute Threat Inspection'}</span>
            </button>

            {err && (
              <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-400 flex items-center gap-2">
                <AlertOctagon className="h-4 w-4 shrink-0" />
                <span>{err}</span>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Detailed Verdict Output */}
        <div className="lg:col-span-7 space-y-5">
          {!res && (
            <div className="flex h-96 flex-col items-center justify-center gap-3 rounded-2xl border border-cyber-border bg-cyber-panel/40 p-8 text-center text-slate-500">
              <Sparkles className="h-10 w-10 text-cyber-accent/40 animate-cyber-pulse" />
              <h3 className="text-base font-bold text-slate-300">Inspector Terminal Ready</h3>
              <p className="max-w-md text-xs">
                Select a content type or sample payload on the left and trigger inspection to view risk scores, payment fraud alerts, policy signals, and safe browsing recommendations.
              </p>
            </div>
          )}

          {res && (
            <div className="space-y-5">
              {/* Verdict Overview Hero Banner */}
              <div className="glass-card rounded-2xl p-6 flex flex-col sm:flex-row items-center gap-6 border-l-4 border-l-cyber-accent">
                <ScoreRing score={res.riskScore} size="lg" />
                <div className="space-y-2 text-center sm:text-left flex-1">
                  <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2.5">
                    <RiskBadge level={res.riskLevel} />
                    <span className="font-mono text-xs font-semibold text-slate-300">
                      “{res.wording}”
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center justify-center sm:justify-start gap-3 font-mono text-xs text-slate-400 pt-1">
                    <span>Confidence: <strong className="text-white">{res.confidence}%</strong></span>
                    <span>Verified: <strong className={res.verified ? 'text-emerald-400' : 'text-slate-300'}>{String(res.verified)}</strong></span>
                    <span>Trusted: <strong className={res.trusted ? 'text-emerald-400' : 'text-slate-300'}>{String(res.trusted)}</strong></span>
                  </div>
                </div>
              </div>

              {/* Payment Details Card */}
              {res.payment && (
                <Card title="UPI / Payment Fraud Vector" icon={CreditCard}>
                  <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs">
                    <div>
                      <dt className="text-slate-500">Payment Scheme</dt>
                      <dd className="font-semibold text-slate-200">{res.payment.scheme} · {res.payment.action}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Target Payee</dt>
                      <dd className="font-semibold text-slate-200 truncate">{res.payment.payeeName || '—'}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Payee UPI VPA</dt>
                      <dd className="font-mono text-cyan-300 truncate">{res.payment.payeeVpa}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Requested Amount</dt>
                      <dd className="font-bold text-amber-400">{res.payment.amount ?? '—'} {res.payment.currency}</dd>
                    </div>
                  </dl>
                  {res.payment.pullPayment && (
                    <div className="mt-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs text-amber-300 font-semibold flex items-center gap-2">
                      <AlertOctagon className="h-4 w-4 shrink-0" />
                      <span>Warning: This payload initiates a PULL payment (Scan to pay/receive money scam).</span>
                    </div>
                  )}
                </Card>
              )}

              {/* Detected Policy Signals */}
              <Card title={`Triggered Security Policies (${res.signals.length})`} icon={ShieldAlert}>
                <div className="space-y-2.5 pt-1">
                  {res.signals.map((s, i) => {
                    const sev = SEV_META[s.severity] || SEV_META.LOW;
                    return (
                      <div key={i} className="rounded-xl border border-cyber-border/70 bg-cyber-dark/60 p-3.5 text-xs space-y-1">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-cyan-400">{s.policyId}</span>
                            <span className={`rounded-md border px-2 py-0.5 text-[10px] font-bold ${sev.cls}`}>
                              {sev.label}
                            </span>
                          </div>
                          <span className="font-mono font-bold text-slate-300">
                            {s.weight > 0 ? '+' : ''}{s.weight} pts
                          </span>
                        </div>
                        <div className="font-bold text-slate-200">{s.name}</div>
                        <div className="text-slate-400 leading-relaxed">{s.detail}</div>
                      </div>
                    );
                  })}
                </div>
              </Card>

              {/* Engine Explanation */}
              <Card title="Engine Technical Assessment" icon={Sparkles}>
                <p className="text-xs text-slate-300 leading-relaxed font-sans">{res.explanation}</p>
              </Card>

              {/* Safe Browsing Recommendations */}
              <Card title="Safe Browsing Action Directives" icon={CheckCircle2}>
                <ul className="space-y-2 text-xs text-slate-300">
                  {res.recommendations.map((r, i) => (
                    <li key={i} className="flex items-start gap-2.5">
                      <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-cyber-accent" />
                      <span>{r}</span>
                    </li>
                  ))}
                </ul>
              </Card>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

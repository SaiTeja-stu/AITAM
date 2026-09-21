import { useEffect, useRef, useState } from 'react';
import { Mail, MapPin, Download, Fingerprint, Route, FileText, Upload, Scale, ShieldCheck, ShieldX, AlertOctagon, Play, Trash2 } from 'lucide-react';
import { api } from '../api.js';
import { Card, RiskBadge, ScoreRing, Spinner } from '../components/ui.jsx';
import SpecularButton from '../components/SpecularButton.jsx';

const AUTH_TONE = {
  PASS: { cls: 'border-cyber-emerald/40 bg-cyber-emerald/10 text-cyber-emerald', Icon: ShieldCheck },
  FAIL: { cls: 'border-cyber-rose/40 bg-cyber-rose/10 text-cyber-rose', Icon: ShieldX },
  SOFTFAIL: { cls: 'border-cyber-amber/40 bg-cyber-amber/10 text-cyber-amber', Icon: AlertOctagon },
  NONE: { cls: 'border-cyber-amber/40 bg-cyber-amber/10 text-cyber-amber', Icon: AlertOctagon },
  UNKNOWN: { cls: 'border-slate-500/30 bg-slate-500/10 text-slate-300', Icon: AlertOctagon },
};

function Fact({ label, value, mono }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</dt>
      <dd className={`truncate text-xs text-slate-200 ${mono ? 'font-mono' : ''}`} title={value || ''}>{value || '—'}</dd>
    </div>
  );
}

function Flag({ children, tone = 'amber' }) {
  const cls = tone === 'rose' ? 'border-cyber-rose/40 text-cyber-rose bg-cyber-rose/10' : 'border-cyber-amber/40 text-cyber-amber bg-cyber-amber/10';
  return <span className={`rounded-md border px-1.5 py-0.5 text-[10px] font-bold ${cls}`}>{children}</span>;
}

export default function EmailForensics() {
  const [samples, setSamples] = useState([]);
  const [raw, setRaw] = useState('');
  const [res, setRes] = useState(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [pdfBusy, setPdfBusy] = useState(false);
  const fileRef = useRef(null);

  useEffect(() => {
    api.forensicsSamples().then(setSamples).catch(() => setSamples([]));
  }, []);

  async function analyze() {
    if (!raw.trim()) return;
    setBusy(true);
    setErr('');
    setRes(null);
    try {
      setRes(await api.forensicsAnalyze(raw));
    } catch (e) {
      setErr(e.message || 'Analysis failed');
    } finally {
      setBusy(false);
    }
  }

  async function downloadPdf() {
    setPdfBusy(true);
    setErr('');
    try {
      const blob = await api.forensicsPdf(raw);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SecureMe_Forensic_Report_${(res?.evidenceSha256 || 'case').slice(0, 10)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch (e) {
      setErr(e.message || 'Could not create the PDF');
    } finally {
      setPdfBusy(false);
    }
  }

  async function loadSample(id) {
    try {
      const s = await api.forensicsSample(id);
      setRaw(s.content);
      setRes(null);
    } catch {
      setErr('Could not load the sample');
    }
  }

  function onFile(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    const r = new FileReader();
    r.onload = () => { setRaw(String(r.result || '')); setRes(null); };
    r.readAsText(f);
    e.target.value = '';
  }

  const origin = res?.originatingHop;
  const originGeo = origin?.geo;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2.5 text-2xl font-bold tracking-tight text-white">
          <Mail className="h-6 w-6 text-cyber-accent" /> E-mail Forensics
        </h1>
        <p className="mt-1 text-xs text-slate-400">
          Paste a raw e-mail or upload an .eml: headers, SPF / DKIM / DMARC, relay path with geolocation, business-e-mail-compromise cues and a court-ready report.
        </p>
      </div>

      <div className="grid gap-8 lg:grid-cols-12">
        {/* input */}
        <div className="space-y-4 lg:col-span-5">
          <div className="glass-card space-y-4 rounded-2xl p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Raw e-mail (.eml)</span>
              <div className="flex items-center gap-3">
                <button type="button" onClick={() => fileRef.current?.click()} className="flex items-center gap-1 text-[11px] text-slate-400 transition-colors hover:text-cyber-accent">
                  <Upload className="h-3 w-3" /> Upload .eml
                </button>
                <button type="button" onClick={() => { setRaw(''); setRes(null); setErr(''); }} className="flex items-center gap-1 text-[11px] text-slate-400 transition-colors hover:text-red-400">
                  <Trash2 className="h-3 w-3" /> Clear
                </button>
              </div>
              <input ref={fileRef} type="file" accept=".eml,.txt,message/rfc822" className="hidden" onChange={onFile} />
            </div>

            {samples.length > 0 && (
              <div>
                <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">Bundled test cases</div>
                <div className="flex flex-wrap gap-1.5">
                  {samples.map((s) => (
                    <button
                      key={s.id}
                      type="button"
                      data-sample={s.id}
                      onClick={() => loadSample(s.id)}
                      title={s.description}
                      className="rounded-lg border border-cyber-border bg-cyber-dark/80 px-2.5 py-1.5 text-left text-[11px] font-semibold text-slate-300 transition-all hover:border-cyber-accent/50 hover:text-cyber-accent"
                    >
                      {s.title}
                    </button>
                  ))}
                </div>
              </div>
            )}

            <textarea
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
              rows={14}
              spellCheck={false}
              className="w-full rounded-xl border border-cyber-border bg-cyber-dark p-3.5 font-mono text-[11px] leading-relaxed text-slate-200 placeholder-slate-600 outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent"
              placeholder={'From: "Name" <sender@example.com>\nReceived: from ... by ...\nSubject: ...\n\nBody...'}
            />

            <SpecularButton
              onClick={analyze}
              disabled={busy || !raw.trim()}
              size="lg"
              lineColor="#63e31a"
              baseColor="#1c5a12"
              radius={14}
              className="w-full font-bold shadow-cyber-glow"
            >
              {busy ? <Spinner className="h-4 w-4 text-cyan-400" /> : <Play className="h-4 w-4 fill-cyan-400 text-cyan-400" />}
              <span className="text-white">{busy ? 'Tracing headers…' : 'Analyze e-mail'}</span>
            </SpecularButton>

            {err && (
              <div className="flex items-center gap-2 rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-400">
                <AlertOctagon className="h-4 w-4 shrink-0" />
                <span>{err}</span>
              </div>
            )}
          </div>
        </div>

        {/* result */}
        <div className="space-y-5 lg:col-span-7">
          {!res && !busy && (
            <div className="flex h-96 flex-col items-center justify-center gap-3 rounded-2xl border border-cyber-border bg-cyber-panel/40 p-8 text-center text-slate-500">
              <Route className="h-10 w-10 text-cyber-accent/40" />
              <h3 className="text-base font-bold text-slate-300">Forensic workbench ready</h3>
              <p className="max-w-md text-xs">Load a bundled case or paste a raw e-mail, then run the analysis to see the verdict, sender authentication, relay trace and the evidence report.</p>
            </div>
          )}

          {res && (
            <div className="space-y-5">
              {/* verdict */}
              <div className="glass-card flex flex-col items-center gap-6 rounded-2xl border-l-4 border-l-cyber-accent p-6 sm:flex-row">
                <ScoreRing score={res.overallRiskScore} size="lg" />
                <div className="flex-1 space-y-2 text-center sm:text-left">
                  <div className="flex flex-wrap items-center justify-center gap-2.5 sm:justify-start">
                    <RiskBadge level={res.riskTier} />
                    <span className="font-mono text-xs font-semibold text-slate-300">Forensic Risk Index {res.overallRiskScore}/100</span>
                  </div>
                  <div className="flex flex-wrap items-center justify-center gap-3 font-mono text-xs text-slate-400 sm:justify-start">
                    <span>BEC score: <strong className="text-white">{res.becScore}</strong></span>
                    <span>VIP impersonation: <strong className={res.isVipImpersonation ? 'text-cyber-rose' : 'text-slate-300'}>{res.isVipImpersonation ? 'yes' : 'no'}</strong></span>
                    <span>Financial coercion: <strong className={res.hasFinancialCoercion ? 'text-cyber-rose' : 'text-slate-300'}>{res.hasFinancialCoercion ? 'yes' : 'no'}</strong></span>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={downloadPdf}
                  disabled={pdfBusy}
                  className="flex shrink-0 items-center gap-2 rounded-xl border border-cyber-accent/40 bg-cyber-accent/10 px-4 py-2.5 text-xs font-bold text-cyber-accent transition-all hover:bg-cyber-accent/20 disabled:opacity-50"
                >
                  {pdfBusy ? <Spinner className="h-4 w-4" /> : <Download className="h-4 w-4" />}
                  Forensic PDF report
                </button>
              </div>

              {/* identity */}
              <Card title="Message identity" icon={Fingerprint}>
                <dl className="grid grid-cols-2 gap-x-6 gap-y-3">
                  <Fact label="Declared sender" value={`${res.fromDisplay || ''} <${res.fromAddress || ''}>`} />
                  <Fact label="Sender domain" value={res.fromDomain} />
                  <Fact label="Reply-To" value={res.replyTo} />
                  <Fact label="Return-Path" value={res.returnPath} />
                  <Fact label="Subject" value={res.subject} />
                  <Fact label="Message-ID" value={res.messageId} mono />
                  <div className="col-span-2">
                    <Fact label="Evidence fingerprint (SHA-256)" value={res.evidenceSha256} mono />
                  </div>
                </dl>
              </Card>

              {/* authentication */}
              <Card title="Sender authentication" icon={ShieldCheck}>
                <div className="grid gap-3 sm:grid-cols-3">
                  {['SPF', 'DKIM', 'DMARC'].map((k) => {
                    const a = res.authMatrix?.[k] || res.authMatrix?.[k.toLowerCase()];
                    const st = (a?.status || 'UNKNOWN').toUpperCase();
                    const tone = AUTH_TONE[st] || AUTH_TONE.UNKNOWN;
                    const T = tone.Icon;
                    return (
                      <div key={k} data-auth={k} className={`rounded-xl border p-3 ${tone.cls}`}>
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-sm font-bold">{k}</span>
                          <T className="h-4 w-4" />
                        </div>
                        <div className="mt-1 text-xs font-bold">{st}</div>
                        <div className="mt-1 line-clamp-3 text-[11px] leading-snug text-slate-300/80">{a?.details || '—'}</div>
                      </div>
                    );
                  })}
                </div>
              </Card>

              {/* relay trace */}
              <Card title={`Relay path and origin (${res.relayHops?.length || 0} hops)`} icon={MapPin}>
                {origin && (
                  <div className="mb-4 rounded-xl border border-cyber-rose/30 bg-cyber-rose/5 p-3.5 text-xs text-slate-200">
                    <span className="font-bold text-cyber-rose">Likely origin: </span>
                    {origin.ip} · {originGeo?.city || 'Unknown city'}, {originGeo?.country || 'Unknown country'}
                    {originGeo?.isp ? ` · ${originGeo.isp}` : ''}{originGeo?.asn ? ` (${originGeo.asn})` : ''}
                    <div className="mt-1 text-[11px] text-slate-400">An investigative lead from the earliest public hop, not proof of identity.</div>
                  </div>
                )}
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-cyber-border/60 text-[10px] uppercase tracking-wider text-slate-500">
                        <th className="py-2 pr-3">Hop</th><th className="pr-3">IP address</th><th className="pr-3">Location</th><th className="pr-3">Network</th><th>Flags</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(res.relayHops || []).map((h) => (
                        <tr key={h.hopNumber} className="border-b border-cyber-border/30 align-top">
                          <td className="py-2 pr-3 font-mono text-slate-300">{h.hopNumber}</td>
                          <td className="pr-3 font-mono text-slate-200">{h.ip || '—'}</td>
                          <td className="pr-3 text-slate-200">{h.geo?.isPrivate ? 'Private network' : [h.geo?.city, h.geo?.country].filter(Boolean).join(', ') || '—'}</td>
                          <td className="pr-3 text-slate-400">{[h.geo?.asn, h.geo?.isp].filter(Boolean).join(' ') || '—'}</td>
                          <td>
                            <div className="flex flex-wrap gap-1">
                              {h.isOriginating && <Flag tone="rose">ORIGIN</Flag>}
                              {h.geo?.isTorOrProxy && <Flag tone="rose">TOR / PROXY</Flag>}
                              {h.geo?.isDatacenter && <Flag>DATACENTER</Flag>}
                              {h.isSuspicious && !h.geo?.isTorOrProxy && <Flag>SUSPICIOUS</Flag>}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>

              {/* reasons */}
              <Card title="Risk indicators" icon={AlertOctagon}>
                <ul className="space-y-2 text-xs text-slate-300">
                  {(res.riskFactors || []).map((f, i) => (
                    <li key={i} className="flex items-start gap-2.5">
                      <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-cyber-accent" />
                      <span>{f}</span>
                    </li>
                  ))}
                  {(res.riskFactors || []).length === 0 && <li className="text-slate-500">No risk indicators found.</li>}
                </ul>
                {(res.campaignMatches || []).length > 0 && (
                  <div className="mt-4 rounded-xl border border-cyber-amber/30 bg-cyber-amber/5 p-3 text-xs text-slate-300">
                    <span className="font-bold text-cyber-amber">Repeat campaign: </span>
                    {res.campaignMatches.length} earlier case(s) share this {res.campaignMatches[0].matchedOn === 'SAME_ORIGIN_IP' ? 'origin IP' : 'sender domain'}.
                  </div>
                )}
              </Card>

              {res.section65bLegalSummary && (
                <Card title="Evidence summary (Section 63 BSA)" icon={Scale}>
                  <p className="whitespace-pre-line text-[11px] leading-relaxed text-slate-400">{res.section65bLegalSummary}</p>
                </Card>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

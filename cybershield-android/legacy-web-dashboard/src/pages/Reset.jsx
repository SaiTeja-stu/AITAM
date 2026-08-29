import { useEffect, useState } from 'react';
import { Shield, KeyRound, Mail, Lock, CheckCircle2, AlertOctagon } from 'lucide-react';
import { api } from '../api.js';
import { Spinner } from '../components/ui.jsx';

export default function Reset() {
  const params = new URLSearchParams(window.location.search);
  const [email, setEmail] = useState(params.get('email') || '');
  const [code, setCode] = useState(params.get('code') || '');
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [ok, setOk] = useState(false);

  useEffect(() => {
    document.title = 'Reset Password — Cyber Shield';
  }, []);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setMsg('');
    try {
      const r = await api.resetPassword(email.trim(), code.trim(), pw);
      setMsg(r.message || 'Password updated.');
      setOk(true);
    } catch (err) {
      setMsg(err.message || 'That code is invalid or has expired.');
      setOk(false);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-cyber-dark px-4 bg-grid-pattern">
      <div className="glass-card relative z-10 w-full max-w-md rounded-3xl p-8 border border-cyber-border/80 shadow-2xl space-y-6">
        <div className="flex flex-col items-center text-center space-y-3">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-cyber-accent to-cyber-indigo p-0.5 shadow-cyber-glow">
            <div className="flex h-full w-full items-center justify-center rounded-[14px] bg-cyber-dark">
              <Shield className="h-7 w-7 text-cyber-accent" />
            </div>
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white">Reset Account Password</h1>
            <p className="text-xs text-slate-400">Cyber Shield Security Recovery Protocol</p>
          </div>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-400">
              Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
              <input
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full rounded-xl border border-cyber-border bg-cyber-dark/80 pl-10 pr-4 py-2.5 text-xs text-slate-200 placeholder-slate-600 outline-none focus:border-cyber-accent font-mono"
              />
            </div>
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-400">
              6-Digit Security Code
            </label>
            <div className="relative">
              <KeyRound className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
              <input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                maxLength={6}
                className="w-full rounded-xl border border-cyber-border bg-cyber-dark/80 pl-10 pr-4 py-2.5 text-xs font-mono tracking-widest text-cyber-accent outline-none focus:border-cyber-accent"
              />
            </div>
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-400">
              New Password (12+ chars)
            </label>
            <div className="relative">
              <Lock className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
              <input
                type="password"
                value={pw}
                onChange={(e) => setPw(e.target.value)}
                className="w-full rounded-xl border border-cyber-border bg-cyber-dark/80 pl-10 pr-4 py-2.5 text-xs text-slate-200 placeholder-slate-600 outline-none focus:border-cyber-accent font-mono"
              />
            </div>
          </div>

          {msg && (
            <div
              className={`rounded-xl border p-3 text-xs flex items-center gap-2 ${
                ok
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                  : 'border-red-500/30 bg-red-500/10 text-red-400'
              }`}
            >
              {ok ? <CheckCircle2 className="h-4 w-4 shrink-0" /> : <AlertOctagon className="h-4 w-4 shrink-0" />}
              <span>{msg}</span>
            </div>
          )}

          {ok ? (
            <a
              href="/"
              className="flex w-full items-center justify-center rounded-xl bg-gradient-to-r from-cyber-accent to-cyber-indigo py-3 text-sm font-bold text-slate-950 transition-all hover:opacity-90 shadow-cyber-glow"
            >
              Return to Console Sign In
            </a>
          ) : (
            <button
              disabled={busy || pw.length < 12 || code.length !== 6}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyber-accent to-cyber-indigo py-3 text-sm font-bold text-slate-950 transition-all hover:opacity-90 disabled:opacity-50 shadow-cyber-glow"
            >
              {busy && <Spinner className="h-4 w-4 text-slate-950" />} Update Account Password
            </button>
          )}
        </form>
      </div>
    </div>
  );
}

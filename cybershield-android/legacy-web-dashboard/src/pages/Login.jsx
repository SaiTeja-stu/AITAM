import { useState } from 'react';
import { Lock, User, KeyRound, AlertOctagon, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../auth.jsx';
import { api } from '../api.js';
import { Spinner } from '../components/ui.jsx';
import SpecularButton from '../components/SpecularButton.jsx';
import logoImg from '../assets/logo.jpg';

export default function Login() {
  const { login, error } = useAuth();
  const [loginId, setLoginId] = useState('admin');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [forgot, setForgot] = useState(false);
  const [note, setNote] = useState('');

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setNote('');
    if (forgot) {
      try {
        const r = await api.forgotPassword(loginId.trim());
        setNote(r.message || 'If that email is registered, a reset code has been sent.');
      } catch {
        setNote('Could not send a reset code right now.');
      }
    } else {
      await login(loginId, password);
    }
    setBusy(false);
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-cyber-dark px-4 bg-grid-pattern">
      {/* Background ambient glow */}
      <div className="absolute h-96 w-96 rounded-full bg-cyber-accent/10 blur-3xl pointer-events-none" />

      <form
        onSubmit={submit}
        className="glass-card relative z-10 w-full max-w-md rounded-3xl p-8 border border-cyber-border/80 shadow-2xl space-y-6"
      >
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center space-y-3">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-cyber-accent to-cyber-indigo p-0.5 shadow-cyber-glow overflow-hidden">
            <img src={logoImg} alt="Cyber Shield Admin" className="h-full w-full object-cover rounded-[14px]" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white">CYBER SHIELD SOC</h1>
            <p className="text-xs text-slate-400">Threat Intelligence & Operations Terminal</p>
          </div>
        </div>

        {/* Input Fields */}
        <div className="space-y-4 pt-2">
          <div>
            <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-400">
              {forgot ? 'Account Email Address' : 'Username or Email'}
            </label>
            <div className="relative">
              <User className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
              <input
                value={loginId}
                onChange={(e) => setLoginId(e.target.value)}
                className="w-full rounded-xl border border-cyber-border bg-cyber-dark/80 pl-10 pr-4 py-2.5 text-xs text-slate-200 placeholder-slate-600 outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent font-mono"
                autoComplete="username"
                placeholder="Enter admin or email address…"
              />
            </div>
          </div>

          {!forgot && (
            <div>
              <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-400">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full rounded-xl border border-cyber-border bg-cyber-dark/80 pl-10 pr-4 py-2.5 text-xs text-slate-200 placeholder-slate-600 outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent font-mono"
                  autoComplete="current-password"
                  placeholder="••••••••••••"
                />
              </div>
            </div>
          )}
        </div>

        {/* Alerts */}
        {error && !forgot && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-400 flex items-center gap-2">
            <AlertOctagon className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
        {note && (
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-400 flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>{note}</span>
          </div>
        )}

        {/* Action Button */}
        <SpecularButton
          type="submit"
          disabled={busy}
          size="lg"
          lineColor="#38bdf8"
          baseColor="#0369a1"
          textColor="#0284c7"
          radius={14}
          className="w-full font-bold shadow-cyber-glow"
        >
          {busy ? <Spinner className="h-4 w-4 text-cyan-400" /> : <KeyRound className="h-4 w-4 text-cyan-400" />}
          <span className="text-white">{forgot ? 'Send Password Reset Code' : 'Authenticate Console'}</span>
        </SpecularButton>

        <button
          type="button"
          onClick={() => {
            setForgot(!forgot);
            setNote('');
          }}
          className="w-full text-center text-xs font-semibold text-slate-400 hover:text-cyber-accent transition-colors"
        >
          {forgot ? '← Back to Sign In' : 'Forgot account password?'}
        </button>

        <div className="border-t border-cyber-border/60 pt-4 text-center text-[11px] text-slate-500">
          Cyber Shield Protection Platform · Port 8899 Security Gate
        </div>
      </form>
    </div>
  );
}

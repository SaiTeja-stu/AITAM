import { useState } from 'react';
import { Lock, User, KeyRound, AlertOctagon, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../auth.jsx';
import { api } from '../api.js';
import { Spinner } from '../components/ui.jsx';
import SpecularButton from '../components/SpecularButton.jsx';
import Aurora from '../components/Aurora.jsx';
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
    <div className="relative isolate flex min-h-screen items-center justify-center overflow-hidden bg-cyber-dark px-4">
      <Aurora />

      <form
        onSubmit={submit}
        className="glass-card relative z-10 w-full max-w-md space-y-6 rounded-3xl p-8 hover:translate-y-0"
      >
        {/* Brand Header */}
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <img src={logoImg} alt="Cyber Shield" className="h-9 w-9 rounded-lg object-cover ring-1 ring-cyber-accent/30" />
            <span className="text-sm font-medium tracking-[0.18em] text-white">
              CYBER<span className="text-cyber-accent">SHIELD</span>
            </span>
          </div>
          <div>
            <div className="label-mono mb-3">[ Operations terminal ]</div>
            <h1 className="display text-[2.6rem]">
              {forgot ? 'Reset' : 'Sign in'}
              <br />
              <span className="dim">{forgot ? 'your password' : 'to the console'}</span>
            </h1>
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
          lineColor="#63e31a"
          baseColor="#1c5a12"
          textColor="#9df05a"
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
          Cyber Shield · part of the Secure Me protection platform
        </div>
      </form>
    </div>
  );
}

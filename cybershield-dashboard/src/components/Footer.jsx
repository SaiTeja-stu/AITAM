import { Link } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';

const CONSOLE = [
  { to: '/', label: 'Overview' },
  { to: '/queue', label: 'Priority Queue' },
  { to: '/analyze', label: 'Analyze Console' },
  { to: '/reports', label: 'Threat Reports' },
];
const COMPANY = [
  { to: '/users', label: 'Users & Data' },
  { to: '/education', label: 'Education' },
];

export default function Footer() {
  return (
    <footer className="relative z-10 mx-auto mt-24 w-full max-w-7xl px-6 pb-36 pt-10 md:px-8">
      <div className="grid gap-12 md:grid-cols-[1.4fr_1fr_1fr]">
        <div>
          <p className="display text-[clamp(2rem,4vw,3.4rem)]">
            Cyber Shield <span className="text-slate-500">—</span>
            <br />
            <span className="dim">
              always-on protection
              <br />
              for every{' '}
              <span className="mx-1 inline-flex h-[0.8em] w-[0.8em] translate-y-[0.06em] items-center justify-center rounded-full border border-cyber-accent/60 align-middle">
                <ShieldCheck className="h-[0.5em] w-[0.5em] text-cyber-accent" />
              </span>{' '}
              Secure Me user
            </span>
          </p>
        </div>

        <div>
          <div className="label-mono mb-5">[ Console ]</div>
          <ul className="space-y-3 text-sm text-slate-200">
            {CONSOLE.map((l) => (
              <li key={l.to}>
                <Link to={l.to} className="transition-colors hover:text-cyber-accent">
                  {l.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>

        <div>
          <div className="label-mono mb-5">[ Platform ]</div>
          <ul className="space-y-3 text-sm text-slate-200">
            {COMPANY.map((l) => (
              <li key={l.to}>
                <Link to={l.to} className="transition-colors hover:text-cyber-accent">
                  {l.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="mt-16 flex flex-col justify-between gap-2 border-t border-cyber-border/60 pt-5 text-[11px] text-slate-500 md:flex-row">
        <span>© 2026 Cyber Shield SOC · part of the Secure Me protection platform</span>
        <span>All rights reserved</span>
      </div>
    </footer>
  );
}

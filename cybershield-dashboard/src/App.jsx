import { useState, useEffect } from 'react';
import { NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  ListFilter,
  SearchCode,
  ShieldAlert,
  GraduationCap,
  LogOut,
  Shield,
  Activity,
  Clock,
  Radio,
} from 'lucide-react';
import { useAuth } from './auth.jsx';
import Login from './pages/Login.jsx';
import Reset from './pages/Reset.jsx';
import Overview from './pages/Overview.jsx';
import Queue from './pages/Queue.jsx';
import AnalyzeConsole from './pages/AnalyzeConsole.jsx';
import Reports from './pages/Reports.jsx';
import Education from './pages/Education.jsx';

const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/queue', label: 'Priority Queue', icon: ListFilter },
  { to: '/analyze', label: 'Analyze Console', icon: SearchCode },
  { to: '/reports', label: 'Threat Reports', icon: ShieldAlert },
  { to: '/education', label: 'Education', icon: GraduationCap },
];

function Shell({ children }) {
  const { logout } = useAuth();
  const location = useLocation();
  const [time, setTime] = useState(new Date().toUTCString());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date().toUTCString().slice(17, 25) + ' UTC'), 1000);
    return () => clearInterval(timer);
  }, []);

  const activeNav = NAV.find((n) => (n.end ? location.pathname === n.to : location.pathname.startsWith(n.to)));

  return (
    <div className="flex min-h-screen bg-cyber-dark text-slate-100 bg-grid-pattern">
      {/* Sleek Vertical Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 flex w-64 flex-col border-r border-cyber-border bg-cyber-panel/90 backdrop-blur-xl">
        {/* Brand Header */}
        <div className="flex h-16 items-center justify-between border-b border-cyber-border px-5">
          <div className="flex items-center gap-3">
            <div className="relative flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyber-accent to-cyber-indigo p-0.5 shadow-cyber-glow">
              <div className="flex h-full w-full items-center justify-center rounded-[10px] bg-cyber-dark">
                <Shield className="h-5 w-5 text-cyber-accent" />
              </div>
            </div>
            <div>
              <span className="font-bold tracking-wider text-white text-base">CYBER SHIELD</span>
              <div className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-cyber-pulse" />
                SOC ENGINE ACTIVE
              </div>
            </div>
          </div>
        </div>

        {/* Navigation Items */}
        <div className="flex-1 space-y-6 px-3 py-6">
          <div>
            <div className="mb-2 px-3 text-[10px] font-bold uppercase tracking-widest text-slate-500">
              Operations Center
            </div>
            <nav className="space-y-1">
              {NAV.map((n) => {
                const Icon = n.icon;
                return (
                  <NavLink
                    key={n.to}
                    to={n.to}
                    end={n.end}
                    className={({ isActive }) =>
                      `group flex items-center gap-3 rounded-xl px-3.5 py-2.5 text-sm font-semibold transition-all duration-200 ${
                        isActive
                          ? 'bg-gradient-to-r from-cyber-accent/20 to-cyber-indigo/10 text-cyber-accent border border-cyber-accent/30 shadow-cyber-glow'
                          : 'text-slate-400 hover:bg-cyber-border/40 hover:text-slate-200'
                      }`
                    }
                  >
                    <Icon className="h-4 w-4 transition-transform group-hover:scale-110" />
                    <span>{n.label}</span>
                  </NavLink>
                );
              })}
            </nav>
          </div>
        </div>

        {/* Bottom User & System Status Card */}
        <div className="border-t border-cyber-border p-4">
          <div className="rounded-xl border border-cyber-border/80 bg-cyber-card/60 p-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center gap-1.5 font-mono text-emerald-400">
                <Radio className="h-3 w-3 animate-cyber-pulse" /> API Port 8899
              </span>
              <span className="rounded bg-cyber-border px-1.5 py-0.5 text-[10px] font-mono text-slate-300">
                v2.0
              </span>
            </div>
            <button
              onClick={logout}
              className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg border border-cyber-border bg-cyber-dark/80 px-3 py-1.5 text-xs font-semibold text-slate-300 transition-all hover:border-red-500/40 hover:bg-red-500/10 hover:text-red-400"
            >
              <LogOut className="h-3.5 w-3.5" />
              Sign Out Administrator
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex flex-1 flex-col pl-64">
        {/* Top Header Bar */}
        <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-cyber-border bg-cyber-dark/80 px-8 backdrop-blur-md">
          <div className="flex items-center gap-3">
            <Activity className="h-4 w-4 text-cyber-accent" />
            <span className="text-sm font-semibold text-slate-400">Dashboard /</span>
            <span className="text-sm font-bold text-white tracking-wide">{activeNav?.label || 'Console'}</span>
          </div>

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 rounded-lg border border-cyber-border bg-cyber-panel/60 px-3 py-1.5 text-xs font-mono text-slate-400">
              <Clock className="h-3.5 w-3.5 text-cyber-accent" />
              <span>{time}</span>
            </div>
            <div className="flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-cyber-pulse" />
              Threat Intel Active
            </div>
          </div>
        </header>

        {/* Dynamic Page Views */}
        <main className="flex-1 p-8">{children}</main>
      </div>
    </div>
  );
}

export default function App() {
  const { isAuthed } = useAuth();
  const { pathname } = useLocation();

  if (pathname === '/reset') return <Reset />;
  if (!isAuthed) return <Login />;

  return (
    <Shell>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/queue" element={<Queue />} />
        <Route path="/analyze" element={<AnalyzeConsole />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/education" element={<Education />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Shell>
  );
}

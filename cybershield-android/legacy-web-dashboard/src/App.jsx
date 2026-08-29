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
import PillNav from './components/PillNav.jsx';
import SpecularButton from './components/SpecularButton.jsx';
import Galaxy from './components/Galaxy.jsx';
import logoImg from './assets/logo.jpg';

const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/queue', label: 'Priority Queue', icon: ListFilter },
  { to: '/analyze', label: 'Analyze Console', icon: SearchCode },
  { to: '/reports', label: 'Threat Reports', icon: ShieldAlert },
  { to: '/education', label: 'Education', icon: GraduationCap },
];

const PILL_NAV_ITEMS = [
  { label: 'Overview', href: '/' },
  { label: 'Priority Queue', href: '/queue' },
  { label: 'Analyze Console', href: '/analyze' },
  { label: 'Threat Reports', href: '/reports' },
  { label: 'Education', href: '/education' },
];

function Shell({ children }) {
  const { logout } = useAuth();
  const location = useLocation();
  const [time, setTime] = useState(new Date().toUTCString());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date().toUTCString().slice(17, 25) + ' UTC'), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="relative isolate flex min-h-screen flex-col bg-cyber-dark text-slate-100 bg-grid-pattern overflow-x-hidden">
      {/* Animated WebGL Galaxy Background Layer */}
      <Galaxy 
        mouseRepulsion={false}
        mouseInteraction={false}
        density={1.8}
        glowIntensity={0.2}
        saturation={0}
        hueShift={50}
        twinkleIntensity={0.2}
        rotationSpeed={0}
        repulsionStrength={2}
        autoCenterRepulsion={0}
        starSpeed={0.1}
        speed={1}
      />

      {/* Top Operations Header Bar with Centered PillNav */}
      <header className="sticky top-0 z-30 flex h-20 items-center justify-between border-b border-cyber-border/80 bg-cyber-dark/60 px-6 md:px-10 backdrop-blur-xl shadow-2xl">
        {/* Brand Header (Left) */}
        <div className="flex items-center gap-3 min-w-[220px]">
          <div className="relative flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyber-accent to-cyber-indigo p-0.5 shadow-cyber-glow overflow-hidden">
            <img src={logoImg} alt="Cyber Shield" className="h-full w-full object-cover rounded-[10px]" />
          </div>
          <div>
            <span className="font-bold tracking-wider text-white text-base">CYBER SHIELD</span>
          </div>
        </div>

        {/* Centered PillNav (Center) */}
        <div className="flex flex-1 justify-center px-4">
          <PillNav
            items={PILL_NAV_ITEMS}
            activeHref={location.pathname}
            baseColor="#0b0f19"
            pillColor="#131b2e"
            hoveredPillTextColor="#38bdf8"
            pillTextColor="#94a3b8"
          />
        </div>

        {/* System Status & Sign Out (Right) */}
        <div className="flex items-center justify-end gap-4 min-w-[220px]">
          <div className="hidden sm:flex items-center gap-2 rounded-lg border border-cyber-border bg-cyber-panel/60 px-3 py-1.5 text-xs font-mono text-slate-400">
            <Clock className="h-3.5 w-3.5 text-cyber-accent" />
            <span>{time}</span>
          </div>
          <SpecularButton
            onClick={logout}
            size="sm"
            lineColor="#f87171"
            baseColor="#7f1d1d"
            radius={12}
            className="border border-cyber-border"
          >
            <LogOut className="h-3.5 w-3.5" />
            <span className="hidden md:inline">Sign Out</span>
          </SpecularButton>
        </div>
      </header>

      {/* Main Content Area - Full Width */}
      <main className="relative z-10 flex-1 p-6 md:p-8 max-w-7xl w-full mx-auto">{children}</main>
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

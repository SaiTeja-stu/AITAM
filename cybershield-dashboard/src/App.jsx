import { useState, useEffect } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { LogOut } from 'lucide-react';
import { useAuth } from './auth.jsx';
import Login from './pages/Login.jsx';
import Reset from './pages/Reset.jsx';
import Overview from './pages/Overview.jsx';
import Queue from './pages/Queue.jsx';
import AnalyzeConsole from './pages/AnalyzeConsole.jsx';
import Reports from './pages/Reports.jsx';
import Education from './pages/Education.jsx';
import Users from './pages/Users.jsx';
import Aurora from './components/Aurora.jsx';
import DockNav from './components/DockNav.jsx';
import Footer from './components/Footer.jsx';
import logoImg from './assets/logo.jpg';

function Shell({ children }) {
  const { logout } = useAuth();
  const location = useLocation();
  const [time, setTime] = useState(new Date().toUTCString().slice(17, 25) + ' UTC');

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date().toUTCString().slice(17, 25) + ' UTC'), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, [location.pathname]);

  return (
    <div className="relative isolate flex min-h-screen flex-col overflow-x-hidden bg-cyber-dark text-slate-100">
      <Aurora />

      {/* Top bar: brand on the left, sign-out pill with the green dot on the right */}
      <header className="relative z-30 flex h-20 items-center justify-between px-6 md:px-10">
        <div className="flex items-center gap-3">
          <img src={logoImg} alt="Cyber Shield" className="h-8 w-8 rounded-lg object-cover ring-1 ring-cyber-accent/30" />
          <span className="text-sm font-medium tracking-[0.18em] text-white">
            CYBER<span className="text-cyber-accent">SHIELD</span>
          </span>
        </div>
        <div className="flex items-center gap-4">
          <span className="hidden font-mono text-[11px] tracking-wider text-slate-500 sm:inline">{time}</span>
          <button type="button" onClick={logout} className="pill-ghost">
            Sign out
            <span className="dot">
              <LogOut className="h-3.5 w-3.5" />
            </span>
          </button>
        </div>
      </header>

      <main className="relative z-10 mx-auto w-full max-w-7xl flex-1 px-6 pt-2 md:px-8">{children}</main>

      <Footer />
      <DockNav />
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
        <Route path="/users" element={<Users />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Shell>
  );
}

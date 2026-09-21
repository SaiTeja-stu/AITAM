import { NavLink } from 'react-router-dom';

const ITEMS = [
  { to: '/', label: 'Overview', end: true },
  { to: '/queue', label: 'Queue' },
  { to: '/analyze', label: 'Analyze' },
  { to: '/forensics', label: 'E-mail Forensics' },
  { to: '/reports', label: 'Reports' },
  { to: '/education', label: 'Education' },
  { to: '/users', label: 'Users & Data' },
];

/** Floating pill navigation fixed to the bottom centre. */
export default function DockNav() {
  return (
    <nav className="pointer-events-none fixed inset-x-0 bottom-5 z-40 flex justify-center px-3">
      <div className="dock pointer-events-auto flex max-w-full items-center gap-1 overflow-x-auto rounded-2xl p-1.5 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
        {ITEMS.map((i) => (
          <NavLink key={i.to} to={i.to} end={i.end} className={({ isActive }) => (isActive ? 'active' : '')}>
            {i.label}
          </NavLink>
        ))}
      </div>
    </nav>
  );
}

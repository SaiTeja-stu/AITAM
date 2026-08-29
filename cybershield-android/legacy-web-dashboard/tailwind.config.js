/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#07090e',
          panel: '#0d111a',
          card: '#131926',
          border: '#1e2638',
          hover: '#263147',
          accent: '#06b6d4',
          indigo: '#6366f1',
          rose: '#f43f5e',
          amber: '#f97316',
          yellow: '#eab308',
          emerald: '#10b981',
        },
      },
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        'cyber-glow': '0 0 25px -5px rgba(6, 182, 212, 0.15)',
        'rose-glow': '0 0 25px -5px rgba(244, 63, 94, 0.25)',
        'amber-glow': '0 0 25px -5px rgba(249, 115, 22, 0.25)',
        'emerald-glow': '0 0 25px -5px rgba(16, 185, 129, 0.25)',
      },
    },
  },
  plugins: [],
};

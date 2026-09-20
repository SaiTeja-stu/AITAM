/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Deep forest-black surfaces with a lime accent.
        cyber: {
          dark: '#030a05',
          panel: '#08140b',
          card: '#0b1a0f',
          border: '#163220',
          hover: '#12281a',
          accent: '#63e31a',
          indigo: '#2f6b3a',
          rose: '#ff5c66',
          amber: '#ff9f43',
          yellow: '#f5d547',
          emerald: '#63e31a',
        },
        // Green-tinted neutrals so every existing text-slate-* / bg-slate-* follows the theme.
        slate: {
          50: '#f3f8f4',
          100: '#e6efe8',
          200: '#cfdcd2',
          300: '#a9bcae',
          400: '#82988a',
          500: '#5f7566',
          600: '#43594a',
          700: '#2c3f33',
          800: '#1a2a20',
          900: '#0e1a12',
          950: '#060d09',
        },
        cyan: {
          300: '#c8f79b',
          400: '#9df05a',
          500: '#63e31a',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        'cyber-glow': '0 0 28px rgba(99, 227, 26, 0.22)',
        'rose-glow': '0 0 18px rgba(255, 92, 102, 0.18)',
        'amber-glow': '0 0 18px rgba(255, 159, 67, 0.18)',
        'emerald-glow': '0 0 18px rgba(99, 227, 26, 0.2)',
      },
    },
  },
  plugins: [],
};

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Dev server proxies API calls to the Spring Boot backend so there are no CORS
// concerns while developing. Change `target` if the backend runs elsewhere.
const BACKEND = process.env.VITE_BACKEND || 'http://localhost:8899';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: BACKEND, changeOrigin: true },
      '/auth': { target: BACKEND, changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
  },
});

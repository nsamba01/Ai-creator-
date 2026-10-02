import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * The SPA is built into `dist/` and served by the Express app in production.
 * In development, the proxy forwards /api to the Node server so cookies stay
 * same-origin (no CORS, no cross-site cookies).
 */
export default defineConfig({
  root: '.',
  plugins: [react()],
  envPrefix: ['VITE_'],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2022',
    reportCompressedSize: false,
    rollupOptions: {
      output: {
        manualChunks: { react: ['react', 'react-dom'] },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      '/api': { target: process.env.API_URL ?? 'http://127.0.0.1:3000', changeOrigin: false },
      '/healthz': { target: process.env.API_URL ?? 'http://127.0.0.1:3000', changeOrigin: false },
      '/readyz': { target: process.env.API_URL ?? 'http://127.0.0.1:3000', changeOrigin: false },
    },
  },
});

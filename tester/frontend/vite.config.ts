import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/',
  server: {
    host: true,
    port: 5173,
  },
  preview: {
    host: true,
    port: 5173,
  },
  resolve: {
    dedupe: ['react', 'react-dom', 'react-is']
  },
  optimizeDeps: {
    include: ['react', 'react-dom', 'react-is', 'recharts']
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        // Only React gets a fixed chunk (every page needs it). Charts (recharts) and PDF
        // export (jspdf) are split automatically so they load only on the pages that use
        // them: forcing them into named chunks made the first page download ~350 KB of
        // gzipped libraries it never used (first load went from ~497 KB to ~144 KB).
        manualChunks(id) {
          const path = id.replace(/\\/g, '/');
          const inPackage = (...names: string[]) => names.some((name) => path.includes(`/node_modules/${name}/`));
          if (inPackage('react', 'react-dom', 'react-router', 'react-router-dom', 'scheduler')) {
            return 'vendor-react';
          }
          return undefined;
        }
      }
    }
  }
})

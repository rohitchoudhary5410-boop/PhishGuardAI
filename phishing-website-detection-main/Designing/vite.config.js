import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    target: 'esnext',
    cssCodeSplit: true,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('react') || id.includes('react-dom') || id.includes('react-router-dom')) {
              return 'vendor-react';
            }
            if (id.includes('recharts')) {
              return 'vendor-charts';
            }
            if (id.includes('framer-motion')) {
              return 'vendor-motion';
            }
            if (id.includes('jspdf') || id.includes('html2canvas')) {
              return 'vendor-export';
            }
            if (id.includes('lucide-react')) {
              return 'vendor-icons';
            }
            return 'vendor-core';
          }
        },
      },
    },
  },
  server: {
    warmup: {
      clientFiles: [
        './src/App.jsx',
        './src/pages/Home/Home.jsx',
        './src/pages/Scanner/Scanner.jsx',
        './src/pages/DeviceScanner/DeviceScanner.jsx',
        './src/pages/EmailScanner/EmailScanner.jsx',
      ],
    },
  },
});

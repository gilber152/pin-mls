import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    host: '0.0.0.0',
    port: 5173,
    allowedHosts: true,
    proxy: {
      '/v1': {
        target: 'http://127.0.0.1:3000',
        changeOrigin: false,
        ws: true,
      },
      '/readyz': {
        target: 'http://127.0.0.1:3000',
        changeOrigin: false,
      },
      '/healthz': {
        target: 'http://127.0.0.1:3000',
        changeOrigin: false,
      },
    },
  },
  worker: {
    format: 'es',
  },
  build: {
    target: 'es2022',
  },
});

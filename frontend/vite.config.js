import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
        // Timeout auf 30 Minuten (Multi-Agent-Analyse: 3 Agenten sequentiell)
        timeout: 1800000,
        proxyTimeout: 1800000,
      }
    }
  }
})

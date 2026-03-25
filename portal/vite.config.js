import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Node-RED (CySOAR) — served by server.cjs in dev
      '/node-red': {
        target: 'http://127.0.0.1:3001',
        changeOrigin: true,
        ws: true,          // proxy WebSocket for Node-RED editor
      },
      // Flask backend — API, auth, OIDC
      '/api':  { target: 'http://127.0.0.1:5252', changeOrigin: true },
      '/auth': { target: 'http://127.0.0.1:5252', changeOrigin: true },
      '/oidc': { target: 'http://127.0.0.1:5252', changeOrigin: true },
    },
  },
})

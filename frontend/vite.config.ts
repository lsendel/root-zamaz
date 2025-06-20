import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Environment-based configuration - directly connect to Go server on port 3001
const BACKEND_PORT = process.env.VITE_BACKEND_PORT || process.env.BACKEND_PORT || '3001'
const BACKEND_HOST = process.env.VITE_BACKEND_HOST || 'localhost'
const BACKEND_URL = `http://${BACKEND_HOST}:${BACKEND_PORT}`

console.log(`🔗 Proxying /api requests directly to Go server: ${BACKEND_URL}`)

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: BACKEND_URL,
        changeOrigin: true,
        secure: false,
        configure: (proxy, _options) => {
          proxy.on('error', (err, _req, _res) => {
            console.error('🚨 Proxy error:', err.message)
            console.log(`💡 Make sure backend is running on ${BACKEND_URL}`)
          })
          proxy.on('proxyReq', (proxyReq, req, _res) => {
            console.log(`🔄 Proxying ${req.method} ${req.url} → ${BACKEND_URL}${req.url}`)
          })
        }
      }
    }
  },
  build: {
    outDir: 'dist',
    sourcemap: true
  },
  define: {
    // Inject backend URL into the app for runtime use
    __BACKEND_URL__: JSON.stringify(BACKEND_URL),
    __DEV_MODE__: JSON.stringify(process.env.NODE_ENV === 'development')
  }
})

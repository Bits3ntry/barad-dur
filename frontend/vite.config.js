import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Dev-only: keeps the platform API same-origin so the browser never
      // sees cross-origin requests during F4 verification.
      '/api': 'http://127.0.0.1:8090',
    },
  },
})

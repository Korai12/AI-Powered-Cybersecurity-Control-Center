import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiTarget = env.VITE_DEV_API_BASE_URL || 'http://localhost:8000'
  const wsTarget =
    env.VITE_DEV_WS_BASE_URL ||
    apiTarget.replace(/^http:\/\//i, 'ws://').replace(/^https:\/\//i, 'wss://')

  return {
    plugins: [react()],

    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },

    server: {
      host: '0.0.0.0',
      port: 5173,
      strictPort: true,
      proxy: {
        '/api': {
          target: apiTarget,
          changeOrigin: true,
        },
        '/auth': {
          target: apiTarget,
          changeOrigin: true,
        },
        '/ws': {
          target: wsTarget,
          ws: true,
          changeOrigin: true,
        },
      },
    },

    preview: {
      host: '0.0.0.0',
      port: 4173,
      strictPort: true,
    },

    build: {
      outDir: 'dist',
      sourcemap: false,
      emptyOutDir: true,
    },
  }
})
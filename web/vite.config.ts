import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'
import { fileURLToPath } from 'url'

// 获取 __dirname 的等价实现
const __dirname = fileURLToPath(new URL('.', import.meta.url))

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, './src')
    }
  },
  server: {
    port: 3000,
    proxy: {
      '/auth': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        // rewrite: (path) => path.replace(/^\/api/, '')
      }
    }
  },
  optimizeDeps: {
    include: ['vue', 'vue-router', 'pinia', 'axios']
  }
}) 
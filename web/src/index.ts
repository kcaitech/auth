import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import axios from 'axios'
import { useAuthStore } from './stores/auth'

// 设置 axios 默认值
axios.defaults.baseURL = import.meta.env.VITE_API_URL || '/api'

// 从本地存储中获取 token 并设置 axios 默认 headers
const token = localStorage.getItem('token')
if (token) {
  axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
}

const app = createApp(App)
const pinia = createPinia()
app.use(pinia)
app.use(router)

// 初始化认证状态
const initAuth = async () => {
  const authStore = useAuthStore()
  
  // 获取支持的登录方式
  try {
    await authStore.fetchSupportedProviders()
  } catch (error) {
    console.error('获取支持的登录方式失败:', error)
  }
  
  // 如果有token，尝试获取当前用户信息
  if (token) {
    try {
      await authStore.fetchCurrentUser()
    } catch (error) {
      console.error('获取用户信息失败:', error)
    }
  }
}

// 挂载应用前初始化认证
initAuth().finally(() => {
  app.mount('#app')
}) 
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import axios from 'axios'

// 设置 axios 默认值
axios.defaults.baseURL = import.meta.env.VITE_API_URL || '/api'

// 从本地存储中获取 token 并设置 axios 默认 headers
const token = localStorage.getItem('token')
if (token) {
  axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
}

const app = createApp(App)

app.use(createPinia())
app.use(router)

app.mount('#app') 
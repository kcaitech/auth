/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import axios from 'axios'
import i18n, { getPreferredLanguage, setLanguage } from './locales'
import { context } from './context'
import { serverApi } from './api/serverApi'

// 设置 axios 默认值
axios.defaults.baseURL = import.meta.env.VITE_API_URL

// 从本地存储中获取 token 并设置 axios 默认 headers
const token = localStorage.getItem('token')
if (token) {
  axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
}

const app = createApp(App)
const pinia = createPinia()
app.use(pinia)
app.use(router)
app.use(i18n)

// 设置语言
const preferredLanguage = getPreferredLanguage()
setLanguage(preferredLanguage)
document.documentElement.setAttribute('lang', preferredLanguage)

// 初始化认证状态
const initAuth = async () => {

  // 如果有token，尝试获取当前用户信息
  if (token) {
    let user = null
    try {
      user = await serverApi.fetchCurrentUser()
      // 当前已经登陆，直接回调
      if (user) await serverApi.handleLoginRedirect()
    } catch (error) {
      console.error('获取用户信息失败:', error)
    }
    if (!user) {
      // refreshToken
      try {
        const { token } = await serverApi.refreshToken()
        if (token) await serverApi.handleLoginRedirect()
      } catch (error) {
        console.error('刷新token失败:', error)
      }
    }
  }

  // 获取支持的登录方式
  try {
    await context.fetchSupportedProviders()
  } catch (error) {
    console.error('获取支持的登录方式失败:', error)
  }

}

// 挂载应用前初始化认证
initAuth().finally(() => {
  app.mount('#app')
}) 
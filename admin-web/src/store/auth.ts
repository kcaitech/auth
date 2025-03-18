import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import axios from 'axios'
import router from '@/router'

export interface LoginCredentials {
  username: string
  password: string
}

export interface UserInfo {
  username: string
  roles: string[]
}

export const useAuthStore = defineStore('auth', () => {
  // 状态
  const userInfo = ref<UserInfo | null>(null)
  const loading = ref(false)
  const error = ref('')

  // 计算属性
  const isAuthenticated = computed(() => !!userInfo.value)
  const username = computed(() => userInfo.value?.username || '')
  const roles = computed(() => userInfo.value?.roles || [])
  
  // 初始化从localStorage加载用户信息
  function initUserInfo() {
    const storedUser = localStorage.getItem('admin_session')
    if (storedUser) {
      try {
        userInfo.value = JSON.parse(storedUser)
      } catch (e) {
        localStorage.removeItem('admin_session')
      }
    }
  }

  // 登录方法
  async function login(credentials: LoginCredentials) {
    loading.value = true
    error.value = ''

    try {
      const response = await axios.post<UserInfo>('/admin/login', credentials)
      userInfo.value = response.data
      localStorage.setItem('admin_session', JSON.stringify(response.data))
      router.push('/')
      return true
    } catch (e: any) {
      error.value = e.response?.data?.error || '登录失败'
      return false
    } finally {
      loading.value = false
    }
  }

  // 注销方法
  async function logout() {
    try {
      await axios.post('/admin/logout')
    } catch (e) {
      console.error('注销请求失败', e)
    } finally {
      userInfo.value = null
      localStorage.removeItem('admin_session')
      router.push('/login')
    }
  }

  // 验证会话
  async function verifySession() {
    if (!userInfo.value) return false
    
    try {
      await axios.get('/admin/verify')
      return true
    } catch (e) {
      userInfo.value = null
      localStorage.removeItem('admin_session')
      return false
    }
  }

  // 初始化
  initUserInfo()

  return {
    userInfo,
    loading,
    error,
    isAuthenticated,
    username,
    roles,
    login,
    logout,
    verifySession
  }
}) 
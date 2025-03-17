import { defineStore } from 'pinia'
import axios from 'axios'

interface User {
  id: string
  username: string
  email: string
}

interface RegisterForm {
  username: string
  email: string
  password: string
  confirmPassword: string
}

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null as User | null,
    token: localStorage.getItem('token') || '',
    loading: false,
    error: null as string | null
  }),
  
  getters: {
    isAuthenticated: (state) => !!state.token,
    currentUser: (state) => state.user
  },
  
  actions: {
    async login(username: string, password: string) {
      try {
        this.loading = true
        this.error = null
        
        // 这里应该调用实际的 API 端点
        const response = await axios.post('/api/auth/login', {
          username,
          password
        })
        
        const { user, token } = response.data
        
        this.user = user
        this.token = token
        
        // 保存 token 到本地存储
        localStorage.setItem('token', token)
        
        // 设置 axios 默认 headers
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
        
        return user
      } catch (error: any) {
        this.error = error.response?.data?.message || '登录失败，请重试'
        throw new Error(this.error || '登录失败，请重试')
      } finally {
        this.loading = false
      }
    },
    
    async register(registerData: RegisterForm) {
      try {
        this.loading = true
        this.error = null
        
        // 这里应该调用实际的 API 端点
        const response = await axios.post('/api/auth/register', registerData)
        
        return response.data
      } catch (error: any) {
        this.error = error.response?.data?.message || '注册失败，请重试'
        throw new Error(this.error || '注册失败，请重试')
      } finally {
        this.loading = false
      }
    },
    
    async logout() {
      try {
        // 可选：调用登出 API
        await axios.post('/api/auth/logout')
      } catch (error) {
        console.error('登出时发生错误', error)
      } finally {
        // 无论 API 调用是否成功，都清除本地状态
        this.user = null
        this.token = ''
        localStorage.removeItem('token')
        delete axios.defaults.headers.common['Authorization']
      }
    },
    
    async fetchCurrentUser() {
      try {
        if (!this.token) return null
        
        this.loading = true
        const response = await axios.get('/api/auth/me')
        this.user = response.data
        return this.user
      } catch (error) {
        this.logout()
        return null
      } finally {
        this.loading = false
      }
    },
    
    // Google 登录相关方法
    async initGoogleAuth() {
      // 这里应该初始化 Google 认证
      // 实际实现可能需要加载 Google API 客户端库
      return {
        signIn: async () => {
          // 模拟 Google 登录
          return { id: 'google-user-id', name: 'Google User', email: 'google@example.com' }
        }
      }
    },
    
    async handleGoogleLogin(googleUser: any) {
      try {
        this.loading = true
        this.error = null
        
        // 发送 Google 用户信息到后端
        const response = await axios.post('/api/auth/google', {
          token: googleUser.id, // 实际应该使用 googleUser.getAuthResponse().id_token
          email: googleUser.email,
          name: googleUser.name
        })
        
        const { user, token } = response.data
        
        this.user = user
        this.token = token
        localStorage.setItem('token', token)
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
        
        return user
      } catch (error: any) {
        this.error = error.response?.data?.message || 'Google 登录失败'
        throw new Error(this.error || 'Google 登录失败')
      } finally {
        this.loading = false
      }
    },
    
    // 微信登录相关方法
    async getWechatAuthUrl() {
      try {
        const response = await axios.get('/api/auth/wechat/url')
        return response.data.url
      } catch (error: any) {
        this.error = error.response?.data?.message || '获取微信登录链接失败'
        throw new Error(this.error || '获取微信登录链接失败')
      }
    },
    
    async handleWechatLogin(code: string) {
      try {
        this.loading = true
        this.error = null
        
        const response = await axios.post('/api/auth/wechat', { code })
        
        const { user, token } = response.data
        
        this.user = user
        this.token = token
        localStorage.setItem('token', token)
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
        
        return user
      } catch (error: any) {
        this.error = error.response?.data?.message || '微信登录失败'
        throw new Error(this.error || '微信登录失败')
      } finally {
        this.loading = false
      }
    }
  }
}) 
/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

import axios from 'axios'

// Vite环境变量类型声明
declare interface ImportMeta {
  readonly env: {
    readonly VITE_API_BASE_URL: string
  }
}

// 创建 axios 实例
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '',
  timeout: 10000,
  withCredentials: true
})

// 请求拦截器
api.interceptors.request.use(
  config => {
    // 可以在这里添加认证头等逻辑
    return config
  },
  error => {
    return Promise.reject(error)
  }
)

// 响应拦截器
api.interceptors.response.use(
  response => {
    // 调试日志，可以在生产环境中移除
    console.debug(`API响应 [${response.config.url}]:`, response.data)
    return response
  },
  error => {
    // 处理 401 未授权错误
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('admin_session')
      window.location.href = '/login'
    }

    // 调试日志，记录请求错误
    console.error(`API错误 [${error.config?.url}]:`, error.response?.data || error.message)

    return Promise.reject(error)
  }
)

// ===================== 认证相关接口定义 =====================
export interface LoginCredentials {
  username: string
  password: string
}

export interface UserInfo {
  username: string
  roles: string[]
}

// ===================== 其他接口定义 =====================
export interface StatsData {
  total_users: number
  active_users: number
  inactive_users: number
  locked_users: number
  banned_users: number
  new_today: number
  new_this_week: number
  new_this_month: number
  login_today: number
  login_this_week: number
  login_this_month: number
  verified_users: number
  unverified_users: number
  two_factor_enabled: number
  social_users: number
  local_users: number
}

export interface User {
  user_id: string
  status: string
  nickname: string
  avatar: string

  last_login: string | null
  login_attempts: number
  last_attempt: string | null
  created_at: string
  updated_at: string
  [key: string]: any
}

export interface UserListResponse {
  users?: User[]
  data?: User[]
  list?: User[]
  total?: number
  total_count?: number
  count?: number
  page?: number
  page_size?: number
  size?: number
  total_page?: number
  pages?: number
  [key: string]: any // 添加索引签名以支持其他可能存在的字段
}

export interface ActivityData {
  date: string
  new_users: number
  active_users: number
  login_attempts: number
  successful_auth: number
  failed_auth: number
}

export interface SessionData {
  id: string
  user_id: number
  ip: string
  user_agent: string
  expires_at: string
  created_at: string
  updated_at: string
}

export interface JWTSessionData {
  key_id: string
  token_type: string
  issued_at: string
  expires_at: string
  ip?: string
  user_agent?: string
}

export interface UserSessionsResponse {
  sessions: SessionData[]
  jwt_sessions: JWTSessionData[]
}

// ===================== 其他 API 方法 =====================
class ServerApi {
  /**
 * 登录
 */
  async login(credentials: LoginCredentials): Promise<UserInfo> {
    const response = await api.post<UserInfo>('/login', credentials)
    // save the response to localStorage
    localStorage.setItem('admin_session', JSON.stringify(response.data))
    return response.data
  }

  /**
   * 注销
   */
  async logout(): Promise<void> {
    await api.post('/logout')
  }

  /**
   * 验证会话
   */
  async verifySession(): Promise<void> {
    await api.get('/verify')
  }

  // 获取统计数据
  getStats(): Promise<StatsData> {
    return api.get('/stats').then(res => res.data)
  }

  // 获取用户列表
  getUsers(params: { page?: number, size?: number, status?: string, provider?: string, verified?: string, search?: string }): Promise<UserListResponse> {
    return api.get('/users', { params }).then(res => res.data)
  }

  // 获取活跃情况
  getActivity(days: number): Promise<ActivityData[]> {
    return api.get('/activity', { params: { days } }).then(res => res.data)
  }

  // 获取用户会话列表
  getUserSessions(userId: string): Promise<UserSessionsResponse> {
    return api.get(`/user/${userId}/sessions`).then(res => res.data)
  }

  // 终止用户特定会话
  terminateUserSession(userId: string, sessionId: string): Promise<{ message: string }> {
    return api.delete(`/user/${userId}/sessions/${sessionId}`).then(res => res.data)
  }

  // 终止用户所有会话
  terminateAllUserSessions(userId: string): Promise<{ message: string }> {
    return api.delete(`/user/${userId}/sessions`).then(res => res.data)
  }
}

export const serverApi = new ServerApi()
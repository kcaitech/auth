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
    return response
  },
  error => {
    // 处理 401 未授权错误
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('admin_session')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// 接口定义
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
  id: number
  username: string
  email: string
  status: string
  provider: string
  verified: boolean
  created_at: string
  last_login: string | null
  two_factor_enabled?: boolean
  login_attempts?: number
  last_attempt?: string
}

export interface UserListResponse {
  users: User[]
  total: number
  page: number
  page_size: number
  total_page: number
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

// API 方法
export default {
  // 获取统计数据
  getStats(): Promise<StatsData> {
    return api.get('/admin/stats').then(res => res.data)
  },

  // 获取用户列表
  getUsers(params: { page?: number, size?: number, status?: string, provider?: string, verified?: string, search?: string }): Promise<UserListResponse> {
    return api.get('/admin/users', { params }).then(res => res.data)
  },

  // 获取活跃情况
  getActivity(days: number): Promise<ActivityData[]> {
    return api.get('/admin/activity', { params: { days } }).then(res => res.data)
  },

  // 获取用户会话列表
  getUserSessions(userId: number): Promise<UserSessionsResponse> {
    return api.get(`/admin/user/${userId}/sessions`).then(res => res.data)
  },

  // 终止用户特定会话
  terminateUserSession(userId: number, sessionId: string): Promise<{ message: string }> {
    return api.delete(`/admin/user/${userId}/sessions/${sessionId}`).then(res => res.data)
  },

  // 终止用户所有会话
  terminateAllUserSessions(userId: number): Promise<{ message: string }> {
    return api.delete(`/admin/user/${userId}/sessions`).then(res => res.data)
  }
} 
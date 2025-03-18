import axios from 'axios'

// 创建 axios 实例
const api = axios.create({
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

// API 方法
export default {
  // 获取统计数据
  getStats(): Promise<StatsData> {
    return api.get('/api/stats').then(res => res.data)
  },

  // 获取用户列表
  getUsers(params: { page?: number, size?: number, status?: string, provider?: string, verified?: string, search?: string }): Promise<UserListResponse> {
    return api.get('/api/users', { params }).then(res => res.data)
  },

  // 获取活跃情况
  getActivity(days: number): Promise<ActivityData[]> {
    return api.get('/api/activity', { params: { days } }).then(res => res.data)
  }
} 
import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const routes = [
  {
    path: '/',
    redirect: '/login'
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/Login.vue')
  },
  {
    path: '/dashboard',
    name: 'Dashboard',
    component: () => import('../views/Dashboard.vue'),
    meta: { requiresAuth: true }
  },
  {
    path: '/auth/verify-email',
    name: 'EmailVerify',
    component: () => import('../components/auth/EmailVerify.vue')
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: () => import('../views/NotFound.vue')
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 导航守卫
router.beforeEach(async (to, from, next) => {
  const authStore = useAuthStore()
  
  // 如果路由需要认证
  if (to.meta.requiresAuth) {
    // 检查用户是否已登录
    if (authStore.isAuthenticated) {
      // 如果已登录但没有用户信息，尝试获取用户信息
      if (!authStore.currentUser) {
        try {
          await authStore.fetchCurrentUser()
        } catch (error) {
          // 如果获取用户信息失败，重定向到登录页
          return next('/login')
        }
      }
      return next()
    } else {
      // 未登录，重定向到登录页
      return next('/login')
    }
  }
  
  // 如果用户已登录且尝试访问登录页，重定向到仪表盘
  if (authStore.isAuthenticated && to.path === '/login') {
    return next('/dashboard')
  }
  
  next()
})

export default router 
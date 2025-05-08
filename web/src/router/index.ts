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
    path: '/success',
    name: 'Success',
    component: () => import('../views/LoginSuccess.vue'),
    meta: { requiresAuth: true },
    beforeEnter: () => { // 正式环境，如果没有redirect，强制跳转到根路径
      window.location.href = `/`; // 跳转到后端路由
    }
  },
  {
    path: '/verify-email',
    name: 'EmailVerify',
    component: () => import('../components/auth/EmailVerify.vue')
  },
  {
    path: '/weixin/callback',
    name: 'WeixinCallback',
    component: () => import('../views/WeixinCallback.vue')
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: () => import('../views/NotFound.vue'),
    beforeEnter: () => {
      window.location.href = `/`; // 跳转到后端路由
    }
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.VITE_BASE_URL),
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

  next()
})

export default router 
/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

import { serverApi } from '@/api/serverApi'
import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    redirect: '/login',
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/Login.vue'),
    // 记录client_id和redirect_uri
    beforeEnter: () => {
      const urlParams = new URLSearchParams(window.location.search)
      const client_id = urlParams.get('client_id') || ''
      const redirect_uri = urlParams.get('redirect_url') || undefined
      serverApi.updateAuthData(client_id, redirect_uri)
    }
  },
  {
    path: '/verify-email',
    name: 'EmailVerify',
    component: () => import('../components/auth/EmailVerify.vue')
  },
  {
    path: '/wechat/callback',
    name: 'WeixinCallback',
    component: () => import('../components/auth/WeixinCallback.vue'),
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

export default router 
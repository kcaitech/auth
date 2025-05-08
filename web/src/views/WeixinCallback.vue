<template>
  <div class="weixin-callback-container">
    <div v-if="loading" class="loading">
      <div class="spinner"></div>
      <p>{{ $t('auth.processingWeixinLogin') }}</p>
    </div>
    <div v-else-if="error" class="error">
      <p>{{ error }}</p>
      <button @click="goToLogin" class="retry-btn">{{ $t('auth.backToLogin') }}</button>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useI18n } from 'vue-i18n'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()
const { t } = useI18n()

const loading = ref(true)
const error = ref('')

const handleWeixinCallback = async () => {
  try {
    const code = route.query.code as string
    const state = route.query.state as string
    
    if (!code || !state) {
      throw new Error(t('errors.invalidWeixinCallback'))
    }
    
    // 调用后端 API 处理微信登录
    await authStore.handleWeixinCallback(code, state)
    
    // 获取回调 URL
    const redirectUrl = authStore.getRedirectUrl()
    if (redirectUrl) {
      // 如果有回调 URL，则重定向到回调地址
      const token = authStore.token
      const separator = redirectUrl.includes('?') ? '&' : '?'
      const fullUrl = `${redirectUrl}${separator}token=${token}`
      window.location.href = fullUrl
      // 清除重定向 URL
      authStore.clearRedirectUrl()
    } else {
      // 否则重定向到成功页面
      router.push('/success')
    }
  } catch (err: any) {
    error.value = err.message || t('errors.weixinLoginFailed')
  } finally {
    loading.value = false
  }
}

const goToLogin = () => {
  router.push('/login')
}

onMounted(() => {
  handleWeixinCallback()
})
</script>

<style scoped>
.weixin-callback-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 20px;
  text-align: center;
}

.loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 20px;
}

.spinner {
  width: 40px;
  height: 40px;
  border: 4px solid #f3f3f3;
  border-top: 4px solid #07C160;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.error {
  color: #ff4d4f;
  margin-bottom: 20px;
}

.retry-btn {
  padding: 10px 20px;
  background-color: #07C160;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  transition: background-color 0.3s;
}

.retry-btn:hover {
  background-color: #06ae56;
}
</style> 
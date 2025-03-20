<template>
  <div class="google-login-container">
    <div id="google-signin-button" class="google-btn-container"></div>
  </div>
</template>

<script lang="ts" setup>
import { onMounted, defineEmits } from 'vue'
import { useAuthStore } from '@/stores/auth'

const emit = defineEmits<{
  (e: 'login-error', message: string): void
}>()

const authStore = useAuthStore()

// 初始化谷歌登录
onMounted(async () => {
  try {
    console.log('开始初始化谷歌登录...')
    // 检查是否配置了谷歌客户端ID
    if (!import.meta.env.VITE_GOOGLE_CLIENT_ID) {
      console.error('未配置谷歌客户端ID，请在.env文件中设置VITE_GOOGLE_CLIENT_ID')
      emit('login-error', '谷歌登录配置不完整，请联系管理员')
      return
    }
    
    // 使用改进后的renderGoogleButton方法，它会同时处理初始化和渲染
    await authStore.renderGoogleButton('google-signin-button')
    console.log('谷歌登录按钮初始化完成')
  } catch (error: any) {
    console.error('初始化谷歌登录失败:', error.message || error)
    emit('login-error', '加载谷歌登录服务失败')
  }
})
</script>

<style scoped>
.google-login-container {
  width: 100%;
}

.google-btn-container {
  width: 100%;
  height: 44px;
  border-radius: 8px;
  overflow: hidden;
  box-sizing: border-box;
  display: flex;
  justify-content: center;
  align-items: center;
}

:deep(.google-btn-container iframe) {
  width: 100% !important;
}

:deep(.google-btn-container > div) {
  width: 100% !important;
}

@media screen and (max-width: 450px) {
  .google-btn-container {
    transform: scale(0.95);
    transform-origin: center;
  }
}
</style> 
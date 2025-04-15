<template>
  <div class="google-login-container">
    <div id="google-signin-button" class="google-btn-container"></div>
  </div>
</template>

<script lang="ts" setup>
import { onMounted, defineEmits } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useI18n } from 'vue-i18n'

const emit = defineEmits<{
  (e: 'login-success'): void
  (e: 'login-error', message: string): void
}>()

const authStore = useAuthStore()
const { t } = useI18n()

// 初始化谷歌登录
onMounted(async () => {
  try {
    // 使用改进后的renderGoogleButton方法，它会同时处理初始化和渲染
    await authStore.renderGoogleButton('google-signin-button', () => {
      emit('login-success')
    })
    console.log(t('logs.googleInitComplete'))
  } catch (error: any) {
    console.error(t('logs.googleInitFailed'), error.message || error)
    emit('login-error', t('errors.googleLoginFailed'))
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
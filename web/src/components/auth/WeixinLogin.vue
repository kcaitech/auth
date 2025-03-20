<template>
  <div class="weixin-login-container">
    <button @click="handleWechatLogin" :disabled="isLoading" class="social-btn wechat-btn">
      <img src="@/assets/wechat-icon.svg" alt="WeChat" />
      使用微信账号
    </button>
  </div>
</template>

<script lang="ts" setup>
import { ref, defineEmits } from 'vue'
import axios from 'axios'

const emit = defineEmits<{
  (e: 'login-error', message: string): void
}>()

const isLoading = ref(false)

const handleWechatLogin = async () => {
  try {
    isLoading.value = true
    
    // 获取微信登录的URL
    const response = await axios.get('/auth/weixin/url')
    const url = response.data.url
    
    // 重定向到微信登录页面
    window.location.href = url
  } catch (error: any) {
    isLoading.value = false
    emit('login-error', error.response?.data?.message || '微信登录初始化失败，请重试')
  }
}
</script>

<style scoped>
.weixin-login-container {
  width: 100%;
}

.wechat-btn {
  width: 100%;
  height: 44px;
  background: #07C160;
  color: white;
  border: none;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 16px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  text-align: center;
  gap: 8px;
  transition: all 0.3s;
}

.wechat-btn img {
  width: 20px;
  height: 20px;
  margin-right: 4px;
  object-fit: contain;
}

.wechat-btn:hover {
  background: #06ae56;
}

.wechat-btn:disabled {
  background: #92ddb5;
  cursor: not-allowed;
  opacity: 0.8;
}

/* 社交按钮通用样式 */
.social-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 16px;
  font-size: 14px;
  transition: all 0.3s;
  outline: none;
  cursor: pointer;
}
</style> 
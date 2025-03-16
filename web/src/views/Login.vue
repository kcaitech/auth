<template>
  <div class="login-container">
    <h2>登录</h2>
    <form @submit.prevent="handleLogin" class="login-form">
      <div class="form-item">
        <input 
          v-model="username" 
          type="text" 
          placeholder="用户名"
          :class="{ 'error': formErrors.username }"
        >
        <span v-if="formErrors.username" class="error-text">{{ formErrors.username }}</span>
      </div>
      
      <div class="form-item">
        <input 
          v-model="password" 
          type="password" 
          placeholder="密码"
          :class="{ 'error': formErrors.password }"
        >
        <span v-if="formErrors.password" class="error-text">{{ formErrors.password }}</span>
      </div>

      <button type="submit" :disabled="loading">
        {{ loading ? '登录中...' : '登录' }}
      </button>
    </form>
    
    <div class="divider">或</div>
    
    <div class="social-login">
      <button @click="handleGoogleLogin" :disabled="loading" class="google-btn">
        <img src="@/assets/google-icon.svg" alt="Google" />
        Google登录
      </button>
      <button @click="handleWechatLogin" :disabled="loading" class="wechat-btn">
        <img src="@/assets/wechat-icon.svg" alt="WeChat" />
        微信登录
      </button>
    </div>

    <div v-if="errorMessage" class="error-message">
      {{ errorMessage }}
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive } from 'vue'
import { useAuthStore } from '../stores/auth'
import { useRouter } from 'vue-router'

const router = useRouter()
const username = ref('')
const password = ref('')
const loading = ref(false)
const errorMessage = ref('')
const authStore = useAuthStore()

const formErrors = reactive({
  username: '',
  password: ''
})

const validateForm = () => {
  let isValid = true
  formErrors.username = ''
  formErrors.password = ''

  if (!username.value) {
    formErrors.username = '请输入用户名'
    isValid = false
  }
  if (!password.value) {
    formErrors.password = '请输入密码'
    isValid = false
  }

  return isValid
}

const handleLogin = async () => {
  if (!validateForm()) return

  try {
    loading.value = true
    errorMessage.value = ''
    await authStore.login(username.value, password.value)
    router.push('/dashboard')
  } catch (error: any) {
    errorMessage.value = error.message || '登录失败，请重试'
  } finally {
    loading.value = false
  }
}

const handleGoogleLogin = async () => {
  try {
    loading.value = true
    errorMessage.value = ''
    const googleAuth = await authStore.initGoogleAuth()
    const user = await googleAuth.signIn()
    await authStore.handleGoogleLogin(user)
    router.push('/dashboard')
  } catch (error: any) {
    errorMessage.value = 'Google登录失败，请重试'
  } finally {
    loading.value = false
  }
}

const handleWechatLogin = async () => {
  try {
    loading.value = true
    errorMessage.value = ''
    // 获取微信登录二维码
    const authUrl = await authStore.getWechatAuthUrl()
    // 打开微信登录窗口
    window.open(authUrl, 'WeChatLogin', 'width=600,height=600')
    // 监听登录成功消息
    window.addEventListener('message', async (event) => {
      if (event.data.type === 'wechat-login-success') {
        await authStore.handleWechatLogin(event.data.code)
        router.push('/dashboard')
      }
    })
  } catch (error: any) {
    errorMessage.value = '微信登录失败，请重试'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-container {
  max-width: 400px;
  margin: 40px auto;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.1);
}

.login-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.form-item {
  display: flex;
  flex-direction: column;
}

input {
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 4px;
}

input.error {
  border-color: #ff4d4f;
}

.error-text {
  color: #ff4d4f;
  font-size: 12px;
  margin-top: 4px;
}

button {
  padding: 10px;
  border: none;
  border-radius: 4px;
  background: #1890ff;
  color: white;
  cursor: pointer;
}

button:disabled {
  background: #ccc;
  cursor: not-allowed;
}

.divider {
  margin: 20px 0;
  text-align: center;
  color: #999;
}

.social-login {
  display: flex;
  gap: 16px;
}

.social-login button {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}

.google-btn {
  background: white;
  border: 1px solid #ddd;
  color: #333;
}

.wechat-btn {
  background: #07C160;
}

.error-message {
  margin-top: 16px;
  padding: 10px;
  background: #fff2f0;
  border: 1px solid #ffccc7;
  border-radius: 4px;
  color: #ff4d4f;
}
</style>
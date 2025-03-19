<template>
  <div class="login-container">
    <div class="auth-tabs">
      <button 
        :class="['tab-btn', { active: activeTab === 'login' }]" 
        @click="activeTab = 'login'"
      >
        登录
      </button>
      <button 
        :class="['tab-btn', { active: activeTab === 'register' }]" 
        @click="activeTab = 'register'"
      >
        注册
      </button>
    </div>

    <!-- 登录表单 -->
    <form v-if="activeTab === 'login'" @submit.prevent="handleLogin" class="auth-form">
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

      <button type="submit" :disabled="loading" class="submit-btn">
        {{ loading ? '登录中...' : '登录' }}
      </button>
    </form>

    <!-- 注册表单 -->
    <form v-else @submit.prevent="handleRegister" class="auth-form">
      <div class="form-item">
        <input 
          v-model="registerForm.userID" 
          type="text" 
          placeholder="账号ID"
          :class="{ 'error': registerErrors.userID }"
        >
        <span v-if="registerErrors.userID" class="error-text">{{ registerErrors.userID }}</span>
      </div>
      
      <div class="form-item">
        <input 
          v-model="registerForm.nickname" 
          type="text" 
          placeholder="昵称"
          :class="{ 'error': registerErrors.nickname }"
        >
        <span v-if="registerErrors.nickname" class="error-text">{{ registerErrors.nickname }}</span>
      </div>
      
      <div class="form-item">
        <input 
          v-model="registerForm.email" 
          type="email" 
          placeholder="邮箱"
          :class="{ 'error': registerErrors.email }"
        >
        <span v-if="registerErrors.email" class="error-text">{{ registerErrors.email }}</span>
      </div>

      <div class="form-item">
        <input 
          v-model="registerForm.password" 
          type="password" 
          placeholder="密码"
          :class="{ 'error': registerErrors.password }"
        >
        <span v-if="registerErrors.password" class="error-text">{{ registerErrors.password }}</span>
      </div>

      <div class="form-item">
        <input 
          v-model="registerForm.confirmPassword" 
          type="password" 
          placeholder="确认密码"
          :class="{ 'error': registerErrors.confirmPassword }"
        >
        <span v-if="registerErrors.confirmPassword" class="error-text">{{ registerErrors.confirmPassword }}</span>
      </div>

      <button type="submit" :disabled="loading" class="submit-btn">
        {{ loading ? '注册中...' : '注册' }}
      </button>
    </form>
    
    <div class="divider">或</div>
    
    <div class="social-login">
      <!-- 社交登录按钮容器，确保所有按钮宽度一致 -->
      <div class="social-buttons">
        <!-- 谷歌登录按钮容器 -->
        <div id="google-signin-button" class="google-btn-container"></div>
        
        <!-- 微信登录按钮 -->
        <button @click="handleWechatLogin" :disabled="loading" class="social-btn wechat-btn">
          <img src="@/assets/wechat-icon.svg" alt="WeChat" />
          使用微信账号
        </button>
      </div>
    </div>

    <div v-if="errorMessage" class="error-message">
      {{ errorMessage }}
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'
import axios from 'axios'

interface FormErrors {
  username?: string
  userID?: string
  nickname?: string
  password?: string
  email?: string
  confirmPassword?: string
}

interface RegisterForm {
  userID: string
  nickname: string
  email: string
  password: string
  confirmPassword: string
}

const router = useRouter()
const authStore = useAuthStore()
const activeTab = ref<'login' | 'register'>('login')
const username = ref('')
const password = ref('')
const loading = ref(false)
const errorMessage = ref('')

const registerForm = reactive<RegisterForm>({
  userID: '',
  nickname: '',
  email: '',
  password: '',
  confirmPassword: ''
})

const formErrors = reactive<FormErrors>({})
const registerErrors = reactive<FormErrors>({})

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

const handleGoogleLogin = async (response: any) => {
  try {
    if (!response || !response.credential) {
      errorMessage.value = '谷歌登录失败：未获取到凭证'
      return
    }
    
    loading.value = true
    errorMessage.value = ''
    
    // 将JWT令牌发送到后端验证
    const authResponse = await axios.post('/auth/google', {
      credential: response.credential
    })
    
    // 处理登录结果
    const { user, token } = authResponse.data
    
    authStore.user = user
    authStore.token = token
    localStorage.setItem('token', token)
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
    
    // 登录成功后跳转到仪表盘
    router.push('/dashboard')
  } catch (error: any) {
    errorMessage.value = error.message || 'Google登录失败，请重试'
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

const handleRegister = async () => {
  if (!validateRegisterForm()) return

  try {
    loading.value = true
    errorMessage.value = ''
    await authStore.register(registerForm)
    activeTab.value = 'login'
  } catch (error: any) {
    errorMessage.value = error.message || '注册失败，请重试'
  } finally {
    loading.value = false
  }
}

const validateRegisterForm = () => {
  let isValid = true
  registerErrors.userID = ''
  registerErrors.nickname = ''
  registerErrors.email = ''
  registerErrors.password = ''
  registerErrors.confirmPassword = ''

  if (!registerForm.userID) {
    registerErrors.userID = '请输入账号ID'
    isValid = false
  }

  if (!registerForm.nickname) {
    registerErrors.nickname = '请输入昵称'
    isValid = false
  }

  if (!registerForm.email) {
    registerErrors.email = '请输入邮箱'
    isValid = false
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(registerForm.email)) {
    registerErrors.email = '请输入有效的邮箱地址'
    isValid = false
  }

  if (!registerForm.password) {
    registerErrors.password = '请输入密码'
    isValid = false
  } else if (registerForm.password.length < 6) {
    registerErrors.password = '密码长度至少6位'
    isValid = false
  }

  if (!registerForm.confirmPassword) {
    registerErrors.confirmPassword = '请确认密码'
    isValid = false
  } else if (registerForm.password !== registerForm.confirmPassword) {
    registerErrors.confirmPassword = '两次输入的密码不一致'
    isValid = false
  }

  return isValid
}

// 在组件挂载后渲染谷歌登录按钮
onMounted(() => {
  // 确保谷歌库已加载
  authStore.initGoogleAuth().then(() => {
    if (window.google && window.google.accounts && window.google.accounts.id) {
      // 初始化谷歌登录
      window.google.accounts.id.initialize({
        client_id: '你的谷歌客户端ID.apps.googleusercontent.com',
        callback: handleGoogleLogin,
        auto_select: false,
        cancel_on_tap_outside: true
      })
      
      // 渲染登录按钮
      const buttonElement = document.getElementById('google-signin-button')
      if (buttonElement) {
        window.google.accounts.id.renderButton(buttonElement, {
          type: 'standard',
          theme: 'filled_blue',
          size: 'large',
          text: 'continue_with',
          shape: 'rectangular',
          logo_alignment: 'center',
          locale: 'zh_CN',
          width: '100%'
        })
        
        // 为了确保按钮宽度一致，我们监听iframe加载完成
        const observer = new MutationObserver((mutations) => {
          const iframe = buttonElement.querySelector('iframe')
          if (iframe) {
            // iframe.style.width = '100%'
            // iframe.style.height = '0px'
            observer.disconnect()
          }
        })
        
        observer.observe(buttonElement, { childList: true, subtree: true })
      }
    }
  }).catch(error => {
    console.error('加载谷歌登录失败', error)
    errorMessage.value = '加载谷歌登录服务失败'
  })
})
</script>

<style scoped>
.login-container {
  max-width: 400px;
  margin: 40px auto;
  padding: 30px;
  border-radius: 12px;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.1);
  background: white;
}

.auth-tabs {
  display: flex;
  margin-bottom: 24px;
  border-bottom: 1px solid #eee;
}

.tab-btn {
  flex: 1;
  padding: 12px;
  background: none;
  border: none;
  color: #666;
  font-size: 16px;
  cursor: pointer;
  transition: all 0.3s;
}

.tab-btn.active {
  color: #1890ff;
  border-bottom: 2px solid #1890ff;
}

.auth-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

input {
  padding: 12px;
  border: 1px solid #ddd;
  border-radius: 8px;
  font-size: 14px;
  transition: all 0.3s;
}

input:focus {
  outline: none;
  border-color: #1890ff;
  box-shadow: 0 0 0 2px rgba(24,144,255,0.1);
}

input.error {
  border-color: #ff4d4f;
}

.error-text {
  color: #ff4d4f;
  font-size: 12px;
}

.submit-btn {
  padding: 12px;
  border: none;
  border-radius: 8px;
  background: #1890ff;
  color: white;
  font-size: 16px;
  cursor: pointer;
  transition: all 0.3s;
}

.submit-btn:hover {
  background: #40a9ff;
}

.submit-btn:disabled {
  background: #bfbfbf;
  cursor: not-allowed;
}

.divider {
  margin: 24px 0;
  text-align: center;
  color: #999;
  position: relative;
}

.divider::before,
.divider::after {
  content: '';
  position: absolute;
  top: 50%;
  width: 45%;
  height: 1px;
  background: #eee;
}

.divider::before {
  left: 0;
}

.divider::after {
  right: 0;
}

.social-login {
  margin-bottom: 16px;
  width: 100%;
}

.social-buttons {
  display: flex;
  flex-direction: column;
  gap: 16px;
  width: 100%;
}

/* 通用按钮样式 */
.social-btn, 
.google-btn-container {
  width: 100%;
  height: 44px; /* 固定高度 */
  border-radius: 8px;
  overflow: hidden;
  box-sizing: border-box;
}

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

.google-btn-container {
  display: flex;
  justify-content: center;
  align-items: center;
}

.wechat-btn {
  background: #07C160;
  color: white;
  border: none;
  text-align: center;
  font-weight: 500;
  gap: 8px;
}

.wechat-btn img {
  margin-right: 4px;
}

.wechat-btn:hover {
  background: #06ae56;
}

.wechat-btn:disabled {
  background: #92ddb5;
  cursor: not-allowed;
  opacity: 0.8;
}

/* 谷歌按钮样式覆盖 */
:deep(.google-btn-container iframe) {
  width: 100% !important;
  height: 0px !important;
}

:deep(.google-btn-container > div) {
  width: 100% !important;
}

.error-message {
  margin-top: 16px;
  padding: 12px;
  background: #fff2f0;
  border: 1px solid #ffccc7;
  border-radius: 8px;
  color: #ff4d4f;
  font-size: 14px;
}

@media screen and (max-width: 450px) {
  .google-btn-container {
    transform: scale(0.95);
    transform-origin: center;
  }
}

/* 图标样式 */
img {
  width: 20px;
  height: 20px;
  vertical-align: middle;
  object-fit: contain;
}
</style>
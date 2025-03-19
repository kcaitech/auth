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

    <!-- 登录表单容器 -->
    <div v-if="activeTab === 'login'">
      <!-- 登录方式切换 -->
      <div v-if="hasProvider('account') && hasProvider('email')" class="login-type-selector">
        <button 
          :class="['login-type-btn', { active: loginType === 'account' }]" 
          @click="loginType = 'account'"
        >
          账号登录
        </button>
        <button 
          :class="['login-type-btn', { active: loginType === 'email' }]" 
          @click="loginType = 'email'"
        >
          邮箱登录
        </button>
      </div>

      <!-- 账号登录表单 -->
      <form v-if="(loginType === 'account' || !hasProvider('email')) && hasProvider('account')" @submit.prevent="handleLogin" class="auth-form">
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

        <button type="submit" :disabled="isLoading" class="submit-btn">
          {{ isLoading ? '登录中...' : '登录' }}
        </button>
      </form>

      <!-- 邮箱登录表单 -->
      <form v-if="(loginType === 'email' || !hasProvider('account')) && hasProvider('email')" @submit.prevent="handleEmailLogin" class="auth-form">
        <div class="form-item">
          <input 
            v-model="email" 
            type="email" 
            placeholder="邮箱"
            :class="{ 'error': formErrors.email }"
          >
          <span v-if="formErrors.email" class="error-text">{{ formErrors.email }}</span>
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

        <button type="submit" :disabled="isLoading" class="submit-btn">
          {{ isLoading ? '登录中...' : '邮箱登录' }}
        </button>
      </form>
    </div>

    <!-- 注册表单容器 -->
    <div v-if="activeTab === 'register'">
      <!-- 注册方式切换 -->
      <div v-if="hasProvider('account') && hasProvider('email')" class="login-type-selector">
        <button 
          :class="['login-type-btn', { active: registerType === 'account' }]" 
          @click="registerType = 'account'"
        >
          账号注册
        </button>
        <button 
          :class="['login-type-btn', { active: registerType === 'email' }]" 
          @click="registerType = 'email'"
        >
          邮箱注册
        </button>
      </div>

      <!-- 账号注册表单 -->
      <form v-if="(registerType === 'account' || !hasProvider('email')) && hasProvider('account')" @submit.prevent="handleRegister" class="auth-form">
        <div class="form-item">
          <input 
            v-model="registerForm.username" 
            type="text" 
            placeholder="用户名"
            :class="{ 'error': registerErrors.userID }"
          >
          <span v-if="registerErrors.userID" class="error-text">{{ registerErrors.userID }}</span>
        </div>
        
        <!-- <div class="form-item">
          <input 
            v-model="registerForm.nickname" 
            type="text" 
            placeholder="昵称"
            :class="{ 'error': registerErrors.nickname }"
          >
          <span v-if="registerErrors.nickname" class="error-text">{{ registerErrors.nickname }}</span>
        </div> -->
        
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

        <button type="submit" :disabled="isLoading" class="submit-btn">
          {{ isLoading ? '注册中...' : '账号注册' }}
        </button>
      </form>

      <!-- 邮箱注册表单 -->
      <form v-if="(registerType === 'email' || !hasProvider('account')) && hasProvider('email')" @submit.prevent="handleEmailRegister" class="auth-form">
        <div class="form-item">
          <input 
            v-model="emailRegisterForm.nickname" 
            type="text" 
            placeholder="昵称"
            :class="{ 'error': registerErrors.nickname }"
          >
          <span v-if="registerErrors.nickname" class="error-text">{{ registerErrors.nickname }}</span>
        </div>
        
        <div class="form-item">
          <input 
            v-model="emailRegisterForm.email" 
            type="email" 
            placeholder="邮箱"
            :class="{ 'error': registerErrors.email }"
          >
          <span v-if="registerErrors.email" class="error-text">{{ registerErrors.email }}</span>
        </div>

        <div class="form-item">
          <input 
            v-model="emailRegisterForm.password" 
            type="password" 
            placeholder="密码"
            :class="{ 'error': registerErrors.password }"
          >
          <span v-if="registerErrors.password" class="error-text">{{ registerErrors.password }}</span>
        </div>

        <div class="form-item">
          <input 
            v-model="emailRegisterForm.confirmPassword" 
            type="password" 
            placeholder="确认密码"
            :class="{ 'error': registerErrors.confirmPassword }"
          >
          <span v-if="registerErrors.confirmPassword" class="error-text">{{ registerErrors.confirmPassword }}</span>
        </div>

        <button type="submit" :disabled="isLoading" class="submit-btn">
          {{ isLoading ? '注册中...' : '邮箱注册' }}
        </button>
      </form>
    </div>
    
    <!-- 只有在有社交登录方式时才显示分隔线和社交登录按钮 -->
    <div v-if="hasProvider('google') || hasProvider('weixin')" class="divider">或</div>
    
    <div v-if="hasProvider('google') || hasProvider('weixin')" class="social-login">
      <!-- 社交登录按钮容器，确保所有按钮宽度一致 -->
      <div class="social-buttons">
        <!-- 谷歌登录按钮容器 -->
        <div v-if="hasProvider('google')" id="google-signin-button" class="google-btn-container"></div>
        
        <!-- 微信登录按钮 -->
        <button v-if="hasProvider('weixin')" @click="handleWechatLogin" :disabled="isLoading" class="social-btn wechat-btn">
          <img src="@/assets/wechat-icon.svg" alt="WeChat" />
          使用微信账号
        </button>
      </div>
    </div>

    <div v-if="errorMessage" class="error-message">
      {{ errorMessage }}
    </div>
    
    <!-- 加载中提示 -->
    <div v-if="initialLoading" class="loading-container">
      <div class="loading-spinner"></div>
      <p>加载登录选项中...</p>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive, onMounted } from 'vue'
import { useAuthStore, type AuthProvider } from '@/stores/auth'
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

interface AccountRegisterForm {
  username: string
  // nickname: string
  password: string
  confirmPassword: string
}

interface EmailRegisterForm {
  nickname: string
  email: string
  password: string
  confirmPassword: string
}

const router = useRouter()
const authStore = useAuthStore()
const activeTab = ref<'login' | 'register'>('login')
const loginType = ref<'account' | 'email'>('account')
const registerType = ref<'account' | 'email'>('account')
const username = ref('')
const email = ref('')
const password = ref('')
const initialLoading = ref(true)
const isLoading = ref(false)
const errorMessage = ref('')

// 直接使用auth store中的hasProvider方法
const hasProvider = (provider: AuthProvider) => authStore.hasProvider(provider)

const formErrors = reactive<FormErrors>({})

const registerForm = reactive<AccountRegisterForm>({
  username: '',
  // nickname: '',
  password: '',
  confirmPassword: ''
})

const emailRegisterForm = reactive<EmailRegisterForm>({
  nickname: '',
  email: '',
  password: '',
  confirmPassword: ''
})

const registerErrors = reactive<FormErrors>({})

// 加载支持的登录方式
onMounted(async () => {
  try {
    initialLoading.value = true
    await authStore.fetchSupportedProviders()
    
    // 设置默认登录和注册类型
    if (hasProvider('account')) {
      loginType.value = 'account'
      registerType.value = 'account'
    } else if (hasProvider('email')) {
      loginType.value = 'email'
      registerType.value = 'email'
    }
    
    // 如果支持谷歌登录，初始化谷歌登录
    if (hasProvider('google')) {
      await initializeGoogleSignIn()
    }
  } catch (error) {
    console.error('初始化登录页面失败', error)
    errorMessage.value = '加载登录选项失败，请刷新页面重试'
  } finally {
    initialLoading.value = false
  }
})

const validateForm = () => {
  let isValid = true
  
  // 清除之前的错误
  Object.keys(formErrors).forEach(key => delete formErrors[key as keyof FormErrors])
  
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
  try {
    errorMessage.value = ''
    
    // 表单验证
    if (!validateForm()) return
    
    isLoading.value = true
    
    // 调用登录函数
    await authStore.login(username.value, password.value)
    
    // 登录成功，导航到Dashboard
    router.push('/dashboard')
  } catch (error: any) {
    errorMessage.value = error.message || '登录失败，请重试'
  } finally {
    isLoading.value = false
  }
}

const validateEmailForm = () => {
  let isValid = true
  
  // 清除之前的错误
  Object.keys(formErrors).forEach(key => delete formErrors[key as keyof FormErrors])
  
  if (!email.value) {
    formErrors.email = '请输入邮箱'
    isValid = false
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) {
    formErrors.email = '请输入有效的邮箱地址'
    isValid = false
  }
  
  if (!password.value) {
    formErrors.password = '请输入密码'
    isValid = false
  }
  
  return isValid
}

const handleEmailLogin = async () => {
  try {
    errorMessage.value = ''
    
    // 表单验证
    if (!validateEmailForm()) return
    
    isLoading.value = true
    
    // 实际实现邮箱登录逻辑
    await axios.post('/auth/email/login', {
      email: email.value,
      password: password.value
    })
    
    // 登录成功，导航到Dashboard
    router.push('/dashboard')
  } catch (error: any) {
    errorMessage.value = error.response?.data?.message || '邮箱登录失败，请重试'
  } finally {
    isLoading.value = false
  }
}

const validateRegisterForm = () => {
  let isValid = true
  
  // 清除之前的错误
  Object.keys(registerErrors).forEach(key => delete registerErrors[key as keyof FormErrors])
  
  if (!registerForm.username) {
    registerErrors.userID = '请输入用户名'
    isValid = false
  }
  
  // if (!registerForm.nickname) {
  //   registerErrors.nickname = '请输入昵称'
  //   isValid = false
  // }
  
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

const handleRegister = async () => {
  try {
    errorMessage.value = ''
    
    // 表单验证
    if (!validateRegisterForm()) return
    
    isLoading.value = true
    
    // 调用账号注册函数
    await authStore.registerAccount(registerForm)
    
    // 注册成功，显示成功消息并切换到登录标签
    errorMessage.value = '注册成功，请登录您的账号'
    activeTab.value = 'login'
    loginType.value = 'account'
  } catch (error: any) {
    errorMessage.value = error.message || '注册失败，请重试'
  } finally {
    isLoading.value = false
  }
}

const validateEmailRegisterForm = () => {
  let isValid = true
  
  // 清除之前的错误
  Object.keys(registerErrors).forEach(key => delete registerErrors[key as keyof FormErrors])
  
  if (!emailRegisterForm.nickname) {
    registerErrors.nickname = '请输入昵称'
    isValid = false
  }
  
  if (!emailRegisterForm.email) {
    registerErrors.email = '请输入邮箱'
    isValid = false
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailRegisterForm.email)) {
    registerErrors.email = '请输入有效的邮箱地址'
    isValid = false
  }
  
  if (!emailRegisterForm.password) {
    registerErrors.password = '请输入密码'
    isValid = false
  } else if (emailRegisterForm.password.length < 6) {
    registerErrors.password = '密码长度至少6位'
    isValid = false
  }
  
  if (!emailRegisterForm.confirmPassword) {
    registerErrors.confirmPassword = '请确认密码'
    isValid = false
  } else if (emailRegisterForm.password !== emailRegisterForm.confirmPassword) {
    registerErrors.confirmPassword = '两次输入的密码不一致'
    isValid = false
  }
  
  return isValid
}

const handleEmailRegister = async () => {
  try {
    errorMessage.value = ''
    
    // 表单验证
    if (!validateEmailRegisterForm()) return
    
    isLoading.value = true
    
    // 实际实现邮箱注册逻辑
    await axios.post('/auth/email/register', {
      nickname: emailRegisterForm.nickname,
      email: emailRegisterForm.email,
      password: emailRegisterForm.password
    })
    
    // 注册成功，显示成功消息并切换到登录标签
    errorMessage.value = '邮箱注册成功，请登录您的账号'
    activeTab.value = 'login'
    loginType.value = 'email'
  } catch (error: any) {
    errorMessage.value = error.response?.data?.message || '邮箱注册失败，请重试'
  } finally {
    isLoading.value = false
  }
}

// 初始化谷歌登录
const initializeGoogleSignIn = async () => {
  try {
    await authStore.initGoogleAuth()
    console.log('初始化谷歌登录')
    // 确保谷歌库已加载
    if (window.google && window.google.accounts && window.google.accounts.id) {
      const googleButton = document.getElementById('google-signin-button')
      if (googleButton) {
        console.log('渲染谷歌登录按钮')
        window.google.accounts.id.renderButton(googleButton, {
          type: 'standard',
          shape: 'rectangular',
          theme: 'filled_blue',
          text: 'continue_with',
          size: 'large',
          width: '100%',
          locale: 'zh_CN',
          logo_alignment: 'center',
        })
      }
    }
  } catch (error) {
    console.error('加载谷歌登录失败', error)
    errorMessage.value = '加载谷歌登录服务失败'
  }
}

const handleWechatLogin = async () => {
  try {
    errorMessage.value = ''
    isLoading.value = true
    
    // 获取微信登录的URL
    const response = await axios.get('/auth/weixin/url')
    const url = response.data.url
    
    // 重定向到微信登录页面
    window.location.href = url
  } catch (error: any) {
    errorMessage.value = error.response?.data?.message || '微信登录初始化失败，请重试'
    isLoading.value = false
  }
}
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

.login-type-selector {
  display: flex;
  margin-bottom: 20px;
  background: #f5f5f5;
  border-radius: 8px;
  overflow: hidden;
}

.login-type-btn {
  flex: 1;
  padding: 10px;
  background: none;
  border: none;
  color: #666;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.3s;
}

.login-type-btn.active {
  background: #1890ff;
  color: white;
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

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 4px solid rgba(0, 0, 0, 0.1);
  border-top: 4px solid #1890ff;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
}
</style>
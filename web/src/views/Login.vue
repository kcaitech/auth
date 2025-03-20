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
      <!-- 使用账号登录组件 -->
      <AccountLogin
        v-if="(loginType === 'account' || !hasProvider('email')) && hasProvider('account')"
        :showLoginTypeSelector="hasProvider('account') && hasProvider('email')"
        @switch-type="loginType = $event"
        @login-success="handleLoginSuccess"
        @login-error="handleLoginError"
      />

      <!-- 使用邮箱登录组件 -->
      <EmailLogin
        v-if="(loginType === 'email' || !hasProvider('account')) && hasProvider('email')"
        :showLoginTypeSelector="hasProvider('account') && hasProvider('email')"
        @switch-type="loginType = $event"
        @login-success="handleLoginSuccess"
        @login-error="handleLoginError"
      />
    </div>

    <!-- 注册表单容器 -->
    <div v-if="activeTab === 'register'">
      <!-- 使用账号注册组件 -->
      <AccountRegister
        v-if="(registerType === 'account' || !hasProvider('email')) && hasProvider('account')"
        :showRegisterTypeSelector="hasProvider('account') && hasProvider('email')"
        @switch-type="registerType = $event"
        @register-success="handleRegisterSuccess"
        @register-error="handleLoginError"
      />

      <!-- 使用邮箱注册组件 -->
      <EmailRegister
        v-if="(registerType === 'email' || !hasProvider('account')) && hasProvider('email')"
        :showRegisterTypeSelector="hasProvider('account') && hasProvider('email')"
        @switch-type="registerType = $event"
        @register-success="handleRegisterSuccess"
        @register-error="handleLoginError"
      />
    </div>
    
    <!-- 只有在有社交登录方式时才显示分隔线和社交登录按钮 -->
    <div v-if="hasProvider('google') || hasProvider('weixin')" class="divider">或</div>
    
    <div v-if="hasProvider('google') || hasProvider('weixin')" class="social-login">
      <!-- 社交登录按钮容器，确保所有按钮宽度一致 -->
      <div class="social-buttons">
        <!-- 使用谷歌登录组件 -->
        <GoogleLogin 
          v-if="hasProvider('google')" 
          @login-error="handleLoginError"
        />
        
        <!-- 使用微信登录组件 -->
        <WeixinLogin 
          v-if="hasProvider('weixin')" 
          @login-error="handleLoginError"
        />
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
import AccountLogin from '@/components/auth/AccountLogin.vue'
import EmailLogin from '@/components/auth/EmailLogin.vue'
import GoogleLogin from '@/components/auth/GoogleLogin.vue'
import WeixinLogin from '@/components/auth/WeixinLogin.vue'
import AccountRegister from '@/components/auth/AccountRegister.vue'
import EmailRegister from '@/components/auth/EmailRegister.vue'

interface FormErrors {
  username?: string
  userID?: string
  nickname?: string
  password?: string
  email?: string
  confirmPassword?: string
}

const router = useRouter()
const authStore = useAuthStore()
const activeTab = ref<'login' | 'register'>('login')
const loginType = ref<'account' | 'email'>('account')
const registerType = ref<'account' | 'email'>('account')
const initialLoading = ref(true)
const isLoading = ref(false)
const errorMessage = ref('')

// 直接使用auth store中的hasProvider方法
const hasProvider = (provider: AuthProvider) => authStore.hasProvider(provider)

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
  } catch (error) {
    console.error('初始化登录页面失败', error)
    errorMessage.value = '加载登录选项失败，请刷新页面重试'
  } finally {
    initialLoading.value = false
  }
})

// 登录成功处理
const handleLoginSuccess = () => {
  errorMessage.value = ''
}

// 登录错误处理
const handleLoginError = (message: string) => {
  errorMessage.value = message
}

// 注册成功处理
const handleRegisterSuccess = () => {
  errorMessage.value = '注册成功，请登录您的账号'
  activeTab.value = 'login'
  if (registerType.value === 'account') {
    loginType.value = 'account'
  } else {
    loginType.value = 'email'
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

.error-message {
  margin-top: 16px;
  padding: 12px;
  background: #fff2f0;
  border: 1px solid #ffccc7;
  border-radius: 8px;
  color: #ff4d4f;
  font-size: 14px;
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
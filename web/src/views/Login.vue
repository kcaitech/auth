<template>
  <div class="login-container">
    <div class="auth-tabs">
      <button 
        :class="['tab-btn', { active: activeTab === 'login' }]" 
        @click="activeTab = 'login'"
      >
        {{ $t('auth.login') }}
      </button>
      <button 
        :class="['tab-btn', { active: activeTab === 'register' }]" 
        @click="activeTab = 'register'"
      >
        {{ $t('auth.register') }}
      </button>
    </div>

    <!-- 登录表单容器 -->
    <div v-if="activeTab === 'login'">
      <!-- 登录方式选择器 -->
      <div v-if="hasMultipleLoginMethods" class="login-type-selector">
        <button 
          :class="['login-type-btn', { active: loginType === 'account' }]" 
          @click="loginType = 'account'"
          v-if="hasProvider('account')"
        >
          {{ $t('auth.accountLogin') }}
        </button>
        <button 
          :class="['login-type-btn', { active: loginType === 'email' }]" 
          @click="loginType = 'email'"
          v-if="hasProvider('email')"
        >
          {{ $t('auth.emailLogin') }}
        </button>
        <button 
          :class="['login-type-btn', { active: loginType === 'phone' }]" 
          @click="loginType = 'phone'"
          v-if="hasProvider('phone')"
        >
          {{ $t('auth.phoneLogin') }}
        </button>
      </div>
    
      <!-- 使用账号登录组件 -->
      <AccountLogin
        v-if="(loginType === 'account' || (!hasProvider('email') && !hasProvider('phone'))) && hasProvider('account')"
        @login-success="handleLoginSuccess"
        @login-error="handleLoginError"
      />

      <!-- 使用邮箱登录组件 -->
      <EmailLogin
        v-if="(loginType === 'email' || (!hasProvider('account') && !hasProvider('phone'))) && hasProvider('email')"
        @login-success="handleLoginSuccess"
        @login-error="handleLoginError"
      />
      
      <!-- 使用手机登录组件 -->
      <PhoneLogin
        v-if="(loginType === 'phone' || (!hasProvider('account') && !hasProvider('email'))) && hasProvider('phone')"
        @login-success="handleLoginSuccess"
        @login-error="handleLoginError"
      />
    </div>

    <!-- 注册表单容器 -->
    <div v-if="activeTab === 'register'">
      <!-- 注册方式选择器 -->
      <div v-if="hasMultipleRegisterMethods" class="register-type-selector">
        <button 
          :class="['register-type-btn', { active: registerType === 'account' }]" 
          @click="registerType = 'account'"
          v-if="hasProvider('account')"
        >
          {{ $t('auth.accountRegister') }}
        </button>
        <button 
          :class="['register-type-btn', { active: registerType === 'email' }]" 
          @click="registerType = 'email'"
          v-if="hasProvider('email')"
        >
          {{ $t('auth.emailRegister') }}
        </button>
        <button 
          :class="['register-type-btn', { active: registerType === 'phone' }]" 
          @click="registerType = 'phone'"
          v-if="hasProvider('phone')"
        >
          {{ $t('auth.phoneRegister') }}
        </button>
      </div>
      
      <!-- 使用账号注册组件 -->
      <AccountRegister
        v-if="(registerType === 'account' || (!hasProvider('email') && !hasProvider('phone'))) && hasProvider('account')"
        @register-success="handleRegisterSuccess"
        @register-error="handleLoginError"
      />

      <!-- 使用邮箱注册组件 -->
      <EmailRegister
        v-if="(registerType === 'email' || (!hasProvider('account') && !hasProvider('phone'))) && hasProvider('email')"
        @register-success="handleRegisterSuccess"
        @register-error="handleLoginError"
      />
      
      <!-- 使用手机注册组件 -->
      <PhoneRegister
        v-if="(registerType === 'phone' || (!hasProvider('account') && !hasProvider('email'))) && hasProvider('phone')"
        @register-success="handleRegisterSuccess"
        @register-error="handleLoginError"
      />
    </div>
    
    <!-- 只有在有社交登录方式时才显示分隔线和社交登录按钮 -->
    <div v-if="(hasProvider('google') || hasProvider('weixin')) && (hasProvider('account') || hasProvider('email') || hasProvider('phone'))" class="divider">{{ $t('common.or') }}</div>
    
    <div v-if="hasProvider('google') || hasProvider('weixin')" class="social-login">
      <!-- 社交登录按钮容器，确保所有按钮宽度一致 -->
      <div class="social-buttons">
        <!-- 使用谷歌登录组件 -->
        <GoogleLogin 
          v-if="hasProvider('google')" 
          @login-error="handleLoginError"
          @login-success="handleLoginSuccess"
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
    <!-- <div v-if="initialLoading" class="loading-container">
      <div class="loading-spinner"></div>
      <p>{{ $t('auth.loadingLoginOptions') }}</p>
    </div> -->
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive, onMounted, computed } from 'vue'
import { useAuthStore, type AuthProvider } from '@/stores/auth'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import AccountLogin from '@/components/auth/AccountLogin.vue'
import EmailLogin from '@/components/auth/EmailLogin.vue'
import PhoneLogin from '@/components/auth/PhoneLogin.vue'
import GoogleLogin from '@/components/auth/GoogleLogin.vue'
import WeixinLogin from '@/components/auth/WeixinLogin.vue'
import AccountRegister from '@/components/auth/AccountRegister.vue'
import EmailRegister from '@/components/auth/EmailRegister.vue'
import PhoneRegister from '@/components/auth/PhoneRegister.vue'

interface FormErrors {
  username?: string
  userID?: string
  nickname?: string
  password?: string
  email?: string
  confirmPassword?: string
}

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()
const { t } = useI18n()
const activeTab = ref<'login' | 'register'>('login')
const loginType = ref<'account' | 'email' | 'phone'>('account')
const registerType = ref<'account' | 'email' | 'phone'>('account')
// const initialLoading = ref(true)
// const isLoading = ref(false)
const errorMessage = ref('')

// 直接使用auth store中的hasProvider方法
const hasProvider = (provider: AuthProvider) => authStore.hasProvider(provider)

// 加载支持的登录方式
onMounted(async () => {
  try {
    // 保存重定向 URL
    const redirectUrl = route.query.redirect as string
    if (redirectUrl) {
      authStore.setRedirectUrl(redirectUrl)
    }
    
    // initialLoading.value = true
    // await authStore.fetchSupportedProviders()
    
    // 检查是否只有社交登录方式
    const hasAccountLogin = hasProvider('account')
    const hasEmailLogin = hasProvider('email')
    const hasPhoneLogin = hasProvider('phone')
    const hasGoogleLogin = hasProvider('google')
    const hasWeixinLogin = hasProvider('weixin')
    
    // 如果只有谷歌登录
    if (!hasAccountLogin && !hasEmailLogin && !hasPhoneLogin && hasGoogleLogin && !hasWeixinLogin) {
      // 等待谷歌登录按钮初始化完成
      await new Promise(resolve => setTimeout(resolve, 1000))
      // 使用 authStore 的方法触发谷歌登录
      try {
        await authStore.renderGoogleButton('google-signin-button', () => {
          handleLoginSuccess()
        })
      } catch (error: any) {
        console.error(t('logs.googleInitFailed'), error.message || error)
        errorMessage.value = t('errors.googleLoginFailed')
      }
    }
    
    // 如果只有微信登录
    if (!hasAccountLogin && !hasEmailLogin && !hasPhoneLogin && !hasGoogleLogin && hasWeixinLogin) {
      // 触发微信登录
      const weixinButton = document.querySelector('.wechat-btn') as HTMLElement
      if (weixinButton) {
        weixinButton.click()
      }
    }
    
    // 设置默认登录和注册类型
    if (hasProvider('account')) {
      loginType.value = 'account'
      registerType.value = 'account'
    } else if (hasProvider('email')) {
      loginType.value = 'email'
      registerType.value = 'email'
    } else if (hasProvider('phone')) {
      loginType.value = 'phone'
      registerType.value = 'phone'
    }
  } catch (error) {
    console.error(t('errors.initLoginPageFailed'), error)
    errorMessage.value = t('errors.loadLoginOptionsFailed')
  } finally {
    // initialLoading.value = false
  }
})

// 登录成功处理
const handleLoginSuccess = () => {
  errorMessage.value = ''
  // 获取回调 URL
  const redirectUrl = authStore.getRedirectUrl()
  if (redirectUrl) {
    // 如果有回调 URL，则重定向到回调地址
    const token = authStore.token
    const separator = redirectUrl.includes('?') ? '&' : '?'
    const fullUrl = `${redirectUrl}${separator}token=${token}`
    // 使用 window.location.href 进行完整的页面跳转
    window.location.href = fullUrl
    // 清除重定向 URL
    authStore.clearRedirectUrl()
  } else {
    // 否则重定向到仪表盘
    router.push('/success')
  }
}

// 登录错误处理
const handleLoginError = (message: string) => {
  errorMessage.value = message
}

// 注册成功处理
const handleRegisterSuccess = () => {
  errorMessage.value = t('auth.registerSuccess')
  activeTab.value = 'login'
  if (registerType.value === 'account') {
    loginType.value = 'account'
  } else if (registerType.value === 'email') {
    loginType.value = 'email'
  } else {
    loginType.value = 'phone'
  }
  handleLoginSuccess()
}

// 计算是否有多种登录方式
const hasMultipleLoginMethods = computed(() => {
  let count = 0
  if (hasProvider('account')) count++
  if (hasProvider('email')) count++
  if (hasProvider('phone')) count++
  return count > 1
})

// 计算是否有多种注册方式
const hasMultipleRegisterMethods = computed(() => {
  let count = 0
  if (hasProvider('account')) count++
  if (hasProvider('email')) count++
  if (hasProvider('phone')) count++
  return count > 1
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

.register-type-selector {
  display: flex;
  margin-bottom: 20px;
  background: #f5f5f5;
  border-radius: 8px;
  overflow: hidden;
}

.register-type-btn {
  flex: 1;
  padding: 10px;
  background: none;
  border: none;
  color: #666;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.3s;
}

.register-type-btn.active {
  background: #1890ff;
  color: white;
}
</style>
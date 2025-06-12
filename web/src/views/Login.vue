/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

<template>
  <!-- 登录表单容器 -->
  <div v-if="shouldShowLoginForm" class="login-container">
    <!-- 登录/注册标签页 -->
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

    <!-- 登录表单 -->
    <div v-if="activeTab === 'login'">
      <!-- 登录方式选择器 -->
      <div v-if="hasMultipleLoginMethods" class="login-type-selector">
        <button 
          v-if="hasAccountLogin"
          :class="['login-type-btn', { active: loginType === 'account' }]" 
          @click="loginType = 'account'"
        >
          {{ $t('auth.accountLogin') }}
        </button>
        <button 
          v-if="hasEmailLogin"
          :class="['login-type-btn', { active: loginType === 'email' }]" 
          @click="loginType = 'email'"
        >
          {{ $t('auth.emailLogin') }}
        </button>
        <button 
          v-if="hasPhoneLogin"
          :class="['login-type-btn', { active: loginType === 'phone' }]" 
          @click="loginType = 'phone'"
        >
          {{ $t('auth.phoneLogin') }}
        </button>
      </div>
    
      <!-- 登录组件 -->
      <AccountLogin
        v-if="(loginType === 'account' || (!hasEmailLogin && !hasPhoneLogin)) && hasAccountLogin"
        @login-success="handleLoginSuccess"
        @login-error="handleLoginError"
      />
      <EmailLogin
        v-if="(loginType === 'email' || (!hasAccountLogin && !hasPhoneLogin)) && hasEmailLogin"
        @login-success="handleLoginSuccess"
        @login-error="handleLoginError"
      />
      <PhoneLogin
        v-if="(loginType === 'phone' || (!hasAccountLogin && !hasEmailLogin)) && hasPhoneLogin"
        @login-success="handleLoginSuccess"
        @login-error="handleLoginError"
      />
    </div>

    <!-- 注册表单 -->
    <div v-if="activeTab === 'register'">
      <!-- 注册方式选择器 -->
      <div v-if="hasMultipleRegisterMethods" class="register-type-selector">
        <button 
          v-if="hasAccountLogin"
          :class="['register-type-btn', { active: registerType === 'account' }]" 
          @click="registerType = 'account'"
        >
          {{ $t('auth.accountRegister') }}
        </button>
        <button 
          v-if="hasEmailLogin"
          :class="['register-type-btn', { active: registerType === 'email' }]" 
          @click="registerType = 'email'"
        >
          {{ $t('auth.emailRegister') }}
        </button>
        <button 
          v-if="hasPhoneLogin"
          :class="['register-type-btn', { active: registerType === 'phone' }]" 
          @click="registerType = 'phone'"
        >
          {{ $t('auth.phoneRegister') }}
        </button>
      </div>
      
      <!-- 注册组件 -->
      <AccountRegister
        v-if="(registerType === 'account' || (!hasEmailLogin && !hasPhoneLogin)) && hasAccountLogin"
        @register-success="handleRegisterSuccess"
        @register-error="handleLoginError"
      />
      <EmailRegister
        v-if="(registerType === 'email' || (!hasAccountLogin && !hasPhoneLogin)) && hasEmailLogin"
        @register-success="handleRegisterSuccess"
        @register-error="handleLoginError"
      />
      <PhoneRegister
        v-if="(registerType === 'phone' || (!hasAccountLogin && !hasEmailLogin)) && hasPhoneLogin"
        @register-success="handleRegisterSuccess"
        @register-error="handleLoginError"
      />
    </div>
    
    <!-- 社交登录 -->
    <div v-if="(hasGoogleLogin || hasWeixinLogin) && (hasAccountLogin || hasEmailLogin || hasPhoneLogin)" 
         class="divider"
    >
      {{ $t('common.or') }}
    </div>
    
    <div v-if="hasGoogleLogin || hasWeixinLogin" class="social-login">
      <div class="social-buttons">
        <GoogleLogin 
          v-if="hasGoogleLogin" 
          @login-error="handleLoginError"
          @login-success="handleLoginSuccess"
        />
        <WeixinLogin 
          v-if="hasWeixinLogin" 
          @login-error="handleLoginError"
        />
      </div>
    </div>

    <!-- 错误信息 -->
    <div v-if="errorMessage" class="error-message">
      {{ errorMessage }}
    </div>
  </div>

  <!-- 仅社交登录容器 -->
  <div v-if="hasGoogleLogin && !shouldShowLoginForm" class="social-buttons2">
    <GoogleLogin 
      v-if="hasGoogleLogin" 
      @login-error="handleLoginError"
      @login-success="handleLoginSuccess"
    />
    <WeixinLogin 
      v-if="hasWeixinLogin" 
      @login-error="handleLoginError"
    />
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted, computed } from 'vue'
import { context } from '@/context'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'

// 组件导入
import AccountLogin from '@/components/auth/AccountLogin.vue'
import EmailLogin from '@/components/auth/EmailLogin.vue'
import PhoneLogin from '@/components/auth/PhoneLogin.vue'
import GoogleLogin from '@/components/auth/GoogleLogin.vue'
import WeixinLogin from '@/components/auth/WeixinLogin.vue'
import AccountRegister from '@/components/auth/AccountRegister.vue'
import EmailRegister from '@/components/auth/EmailRegister.vue'
import PhoneRegister from '@/components/auth/PhoneRegister.vue'
import { AuthProvider, serverApi } from '@/api/serverApi'


const { t } = useI18n()
const route = useRoute()

// 响应式状态
const activeTab = ref<'login' | 'register'>('login')
const loginType = ref<'account' | 'email' | 'phone'>('account')
const registerType = ref<'account' | 'email' | 'phone'>('account')
const errorMessage = ref('')
const shouldShowLoginForm = ref(false)

// 登录方式检查
const hasProvider = (provider: AuthProvider) => context.hasProvider(provider)
const hasAccountLogin = hasProvider('account')
const hasEmailLogin = hasProvider('email')
const hasPhoneLogin = hasProvider('phone')
const hasGoogleLogin = hasProvider('google')
const hasWeixinLogin = hasProvider('weixin')
const hasWeixinMiniLogin = hasProvider('weixin_mini')

// 计算属性
const hasMultipleLoginMethods = computed(() => {
  let count = 0
  if (hasProvider('account')) count++
  if (hasProvider('email')) count++
  if (hasProvider('phone')) count++
  return count > 1
})

const hasMultipleRegisterMethods = computed(() => {
  let count = 0
  if (hasProvider('account')) count++
  if (hasProvider('email')) count++
  if (hasProvider('phone')) count++
  return count > 1
})

const handleWechatLogin = async () => {
  try {
    // 获取微信登录的URL
    const url = await serverApi.getWechatAuthUrl()

    // 获取url中的state
    const cleanUrl = url.split('#')[0]
    const state = cleanUrl.split('state=')[1]
    if (!state) {
      throw new Error(t('errors.wechatLoginFailed'))
    }
    // 使用state存储client_id
    sessionStorage.setItem(state, serverApi.clientId)
    // 重定向到微信登录页面
    // https://open.weixin.qq.com/connect/qrconnect?appid=xxxxx&redirect_uri=https://account.vextra.cn/wechat/callback&response_type=code&scope=snsapi_login&state=123#wechat_redirect
    // 上述地址授权完成后，调转到https://account.vextra.cn/wechat/callback?code=xxx&state=123
    window.location.href = url
  } catch (error: any) {
    console.error(t('errors.wechatLoginFailed'), error)
  }
}

const handleWeixinMiniLogin = async () => {
  try {
    const code = route.query.code as string;
    const url = await serverApi.weixinMiniLogin(code);
  } catch (error: any) {
    console.error(t('errors.wechatMiniLoginFailed'), error)
  }
}

// 生命周期钩子
onMounted(async () => {
  const isMiniProgram = navigator.userAgent.includes("miniProgram");
  try {
    // 如果只有微信登录
    if (!hasAccountLogin && !hasEmailLogin && !hasPhoneLogin && !hasGoogleLogin && hasWeixinLogin && !isMiniProgram) {
      handleWechatLogin()
      return
    }

    if(hasWeixinMiniLogin && isMiniProgram) {
      handleWeixinMiniLogin()
      return
    }
    
    // 如果只有社交登录
    if (!hasAccountLogin && !hasEmailLogin && !hasPhoneLogin) {
      return
    }
    
    shouldShowLoginForm.value = true
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
  }
})

// 事件处理
const handleLoginSuccess = () => {
  errorMessage.value = ''

}

const handleLoginError = (message: string) => {
  errorMessage.value = message
}

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
</script>

<style scoped>
/* 容器样式 */
.login-container,
.social-buttons2 {
  max-width: 400px;
  margin: 40px auto;
  padding: 30px;
  border-radius: 12px;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.1);
  background: white;
}

/* 标签页样式 */
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

/* 登录方式选择器 */
.login-type-selector,
.register-type-selector {
  display: flex;
  margin-bottom: 20px;
  background: #f5f5f5;
  border-radius: 8px;
  overflow: hidden;
}

.login-type-btn,
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

.login-type-btn.active,
.register-type-btn.active {
  background: #1890ff;
  color: white;
}

/* 表单样式 */
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

/* 按钮样式 */
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

/* 分隔线样式 */
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

/* 社交登录样式 */
.social-login {
  margin-bottom: 16px;
  width: 100%;
}

.social-buttons,
.social-buttons2 {
  display: flex;
  flex-direction: column;
  gap: 16px;
  width: 100%;
}

/* 错误信息样式 */
.error-message {
  margin-top: 16px;
  padding: 12px;
  background: #fff2f0;
  border: 1px solid #ffccc7;
  border-radius: 8px;
  color: #ff4d4f;
  font-size: 14px;
}

/* 加载动画样式 */
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
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}
</style>
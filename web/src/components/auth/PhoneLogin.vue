<template>
  <div>
    <!-- 手机登录类型切换 -->
    <div class="phone-login-tabs">
      <button 
        :class="['tab-btn', { active: phoneLoginMethod === 'password' }]" 
        @click="phoneLoginMethod = 'password'"
      >
        {{ $t('auth.passwordLogin') }}
      </button>
      <button 
        :class="['tab-btn', { active: phoneLoginMethod === 'code' }]" 
        @click="phoneLoginMethod = 'code'"
      >
        {{ $t('auth.codeLogin') }}
      </button>
    </div>

    <!-- 手机号密码登录表单 -->
    <form v-if="phoneLoginMethod === 'password'" @submit.prevent="handlePasswordLogin" class="auth-form">
      <div class="form-item">
        <input 
          v-model="passwordForm.phone" 
          type="text" 
          :placeholder="$t('common.phoneNumber')"
          :class="{ 'error': formErrors.phone }"
        >
        <span v-if="formErrors.phone" class="error-text">{{ formErrors.phone }}</span>
      </div>
      
      <div class="form-item">
        <input 
          v-model="passwordForm.password" 
          type="password" 
          :placeholder="$t('common.password')"
          :class="{ 'error': formErrors.password }"
        >
        <span v-if="formErrors.password" class="error-text">{{ formErrors.password }}</span>
      </div>

      <button type="submit" :disabled="isLoading" class="submit-btn">
        {{ isLoading ? $t('common.loading') : $t('auth.login') }}
      </button>
    </form>

    <!-- 手机验证码登录表单 -->
    <form v-if="phoneLoginMethod === 'code'" @submit.prevent="handleCodeLogin" class="auth-form">
      <div class="form-item">
        <input 
          v-model="codeForm.phone" 
          type="text" 
          :placeholder="$t('common.phoneNumber')"
          :class="{ 'error': formErrors.phone }"
        >
        <span v-if="formErrors.phone" class="error-text">{{ formErrors.phone }}</span>
      </div>
      
      <div class="form-item verification-code">
        <input 
          v-model="codeForm.code" 
          type="text" 
          :placeholder="$t('common.verificationCode')"
          :class="{ 'error': formErrors.code }"
        >
        <button 
          type="button" 
          @click="sendVerificationCode" 
          :disabled="cooldown > 0 || !codeForm.phone || isLoading || isSendingCode"
          class="code-btn"
        >
          <span v-if="isSendingCode">{{ $t('common.sending') }}</span>
          <span v-else>{{ cooldown > 0 ? $t('common.secondsRemaining', { seconds: cooldown }) : $t('auth.getVerificationCode') }}</span>
        </button>
        <span v-if="formErrors.code" class="error-text">{{ formErrors.code }}</span>
      </div>

      <button type="submit" :disabled="isLoading" class="submit-btn">
        {{ isLoading ? $t('common.loading') : $t('auth.login') }}
      </button>
    </form>
  </div>
</template>

<script lang="ts" setup>
import { reactive, ref, defineEmits } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

const emit = defineEmits<{
  (e: 'login-success'): void
  (e: 'login-error', message: string): void
}>()

const authStore = useAuthStore()
const router = useRouter()
const { t } = useI18n()

// 手机登录方式 (密码登录 或 验证码登录)
const phoneLoginMethod = ref('password')

// 密码登录表单
const passwordForm = reactive({
  phone: '',
  password: ''
})

// 验证码登录表单
const codeForm = reactive({
  phone: '',
  code: ''
})

// 表单错误
const formErrors = reactive({
  phone: '',
  password: '',
  code: ''
})

// 正在加载
const isLoading = ref(false)

// 验证码冷却时间
const cooldown = ref(0)
let cooldownTimer: number | null = null

// 验证码发送状态
const isSendingCode = ref(false)


// 验证手机号格式
function validatePhone(phone: string): boolean {
  if (!phone) {
    formErrors.phone = t('validation.required', { field: t('common.phoneNumber') })
    return false
  }
  
  // 简单的手机号格式验证（中国大陆手机号）
  const phoneRegex = /^1[3-9]\d{9}$/
  if (!phoneRegex.test(phone)) {
    formErrors.phone = t('validation.invalidPhone')
    return false
  }
  
  formErrors.phone = ''
  return true
}

// 验证密码
function validatePassword(password: string): boolean {
  if (!password) {
    formErrors.password = t('validation.required', { field: t('common.password') })
    return false
  }
  
  if (password.length < 8) {
    formErrors.password = t('validation.passwordLength', { min: 8 })
    return false
  }
  
  formErrors.password = ''
  return true
}

// 验证验证码
function validateCode(code: string): boolean {
  if (!code) {
    formErrors.code = t('validation.required', { field: t('common.verificationCode') })
    return false
  }
  
  if (code.length !== 6 || !/^\d+$/.test(code)) {
    formErrors.code = t('validation.verificationCodeFormat')
    return false
  }
  
  formErrors.code = ''
  return true
}

// 发送验证码
async function sendVerificationCode() {
  if (!validatePhone(codeForm.phone)) return
  
  try {
    isSendingCode.value = true
    await authStore.sendPhoneVerificationCode(codeForm.phone)
    
    // 开始倒计时
    cooldown.value = 60
    cooldownTimer = window.setInterval(() => {
      cooldown.value--
      if (cooldown.value <= 0 && cooldownTimer) {
        clearInterval(cooldownTimer)
        cooldownTimer = null
      }
    }, 1000)
    
  } catch (error: any) {
    emit('login-error', error.message)
  } finally {
    isSendingCode.value = false
  }
}

// 密码登录
async function handlePasswordLogin() {
  // 重置表单错误
  formErrors.phone = ''
  formErrors.password = ''
  
  // 验证表单
  const isPhoneValid = validatePhone(passwordForm.phone)
  const isPasswordValid = validatePassword(passwordForm.password)
  
  if (!isPhoneValid || !isPasswordValid) return
  
  try {
    isLoading.value = true
    const user = await authStore.phoneLogin(passwordForm.phone, passwordForm.password)
    emit('login-success')
  } catch (error: any) {
    emit('login-error', error.message)
  } finally {
    isLoading.value = false
  }
}

// 验证码登录
async function handleCodeLogin() {
  // 重置表单错误
  formErrors.phone = ''
  formErrors.code = ''
  
  // 验证表单
  const isPhoneValid = validatePhone(codeForm.phone)
  const isCodeValid = validateCode(codeForm.code)
  
  if (!isPhoneValid || !isCodeValid) return
  
  try {
    isLoading.value = true
    const user = await authStore.phoneCodeLogin(codeForm.phone, codeForm.code)
    emit('login-success')
    router.push('/dashboard')
  } catch (error: any) {
    emit('login-error', error.message)
  } finally {
    isLoading.value = false
  }
}

</script>

<style scoped>
.phone-login-tabs {
  display: flex;
  margin-bottom: 20px;
}

.phone-login-tabs .tab-btn {
  flex: 1;
  padding: 10px;
  background-color: #f5f5f5;
  border: none;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.3s;
}

.phone-login-tabs .tab-btn.active {
  background-color: #007bff;
  color: white;
}

.verification-code {
  display: flex;
  gap: 10px;
  position: relative;
}

.verification-code input {
  flex: 1;
  padding-right: 110px; /* 为按钮留出空间 */
}

.code-btn {
  position: absolute;
  right: 0;
  top: 0;
  height: 100%;
  white-space: nowrap;
  background-color: #1890ff;
  color: white;
  border: none;
  border-radius: 0 8px 8px 0;
  padding: 0 15px;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.3s;
}

.code-btn:hover:not(:disabled) {
  background-color: #40a9ff;
}

.code-btn:disabled {
  background-color: #bfbfbf;
  cursor: not-allowed;
  opacity: 0.7;
}

.forget-password {
  text-align: right;
  margin-bottom: 15px;
  font-size: 14px;
}

.forget-password a {
  color: #007bff;
  text-decoration: none;
}

/* 模态框样式 */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.modal-content {
  background-color: white;
  padding: 20px;
  border-radius: 5px;
  width: 90%;
  max-width: 400px;
  position: relative;
}

.close-btn {
  position: absolute;
  top: 10px;
  right: 10px;
  background: none;
  border: none;
  font-size: 20px;
  cursor: pointer;
}

.success-message {
  text-align: center;
  padding: 20px 0;
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
</style> 
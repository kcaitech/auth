<template>
  <div>
    <!-- 手机注册表单 -->
    <form @submit.prevent="handleRegister" class="auth-form">
      <div class="form-item">
        <input 
          v-model="formData.phone" 
          type="text" 
          placeholder="手机号"
          :class="{ 'error': formErrors.phone }"
        >
        <span v-if="formErrors.phone" class="error-text">{{ formErrors.phone }}</span>
      </div>
      
      <div class="form-item verification-code">
        <input 
          v-model="formData.code" 
          type="text" 
          placeholder="验证码"
          :class="{ 'error': formErrors.code }"
        >
        <button 
          type="button" 
          @click="sendVerificationCode" 
          :disabled="cooldown > 0 || !formData.phone || isLoading || isSendingCode"
          class="code-btn"
        >
          <span v-if="isSendingCode">发送中...</span>
          <span v-else>{{ cooldown > 0 ? `${cooldown}秒` : '获取验证码' }}</span>
        </button>
        <span v-if="formErrors.code" class="error-text">{{ formErrors.code }}</span>
      </div>
      
      <div class="form-item">
        <input 
          v-model="formData.nickname" 
          type="text" 
          placeholder="昵称"
          :class="{ 'error': formErrors.nickname }"
        >
        <span v-if="formErrors.nickname" class="error-text">{{ formErrors.nickname }}</span>
      </div>
      
      <div class="form-item">
        <input 
          v-model="formData.password" 
          type="password" 
          placeholder="密码"
          :class="{ 'error': formErrors.password }"
        >
        <span v-if="formErrors.password" class="error-text">{{ formErrors.password }}</span>
      </div>
      
      <div class="form-item">
        <input 
          v-model="formData.confirmPassword" 
          type="password" 
          placeholder="确认密码"
          :class="{ 'error': formErrors.confirmPassword }"
        >
        <span v-if="formErrors.confirmPassword" class="error-text">{{ formErrors.confirmPassword }}</span>
      </div>

      <button type="submit" :disabled="isLoading" class="submit-btn">
        {{ isLoading ? '注册中...' : '注册' }}
      </button>
    </form>
    
    <!-- 验证成功提示 -->
    <div v-if="registerSuccess" class="modal-overlay">
      <div class="modal-content success-modal">
        <h3>注册成功!</h3>
        <p>您的手机号注册成功，可以开始登录使用了。</p>
        <button @click="goToLogin" class="submit-btn">去登录</button>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { reactive, ref, defineEmits } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'

const emit = defineEmits<{
  (e: 'register-success'): void
  (e: 'register-error', message: string): void
}>()

const authStore = useAuthStore()
const router = useRouter()

// 注册表单数据
const formData = reactive({
  phone: '',
  code: '',
  nickname: '',
  password: '',
  confirmPassword: '',
  agreement: false
})

// 表单错误
const formErrors = reactive({
  phone: '',
  code: '',
  nickname: '',
  password: '',
  confirmPassword: '',
  agreement: ''
})

// 正在加载
const isLoading = ref(false)

// 验证码冷却时间
const cooldown = ref(0)
let cooldownTimer: number | null = null

// 验证码发送状态
const isSendingCode = ref(false)

// 协议与隐私政策模态框
// const showAgreement = ref(false)
// const showPrivacy = ref(false)

// 注册成功
const registerSuccess = ref(false)

// 验证手机号格式
function validatePhone(phone: string): boolean {
  if (!phone) {
    formErrors.phone = '请输入手机号'
    return false
  }
  
  // 简单的手机号格式验证（中国大陆手机号）
  const phoneRegex = /^1[3-9]\d{9}$/
  if (!phoneRegex.test(phone)) {
    formErrors.phone = '手机号格式不正确'
    return false
  }
  
  formErrors.phone = ''
  return true
}

// 验证验证码
function validateCode(code: string): boolean {
  if (!code) {
    formErrors.code = '请输入验证码'
    return false
  }
  
  if (code.length !== 6 || !/^\d+$/.test(code)) {
    formErrors.code = '验证码应为6位数字'
    return false
  }
  
  formErrors.code = ''
  return true
}

// 验证昵称
function validateNickname(nickname: string): boolean {
  if (!nickname) {
    formErrors.nickname = '请输入昵称'
    return false
  }
  
  if (nickname.length < 2 || nickname.length > 20) {
    formErrors.nickname = '昵称长度应在2-20个字符之间'
    return false
  }
  
  formErrors.nickname = ''
  return true
}

// 验证密码
function validatePassword(password: string): boolean {
  if (!password) {
    formErrors.password = '请输入密码'
    return false
  }
  
  if (password.length < 8) {
    formErrors.password = '密码长度至少为8位'
    return false
  }
  
  formErrors.password = ''
  return true
}

// 验证确认密码
function validateConfirmPassword(password: string, confirmPassword: string): boolean {
  if (!confirmPassword) {
    formErrors.confirmPassword = '请确认密码'
    return false
  }
  
  if (password !== confirmPassword) {
    formErrors.confirmPassword = '两次密码输入不一致'
    return false
  }
  
  formErrors.confirmPassword = ''
  return true
}

// 验证协议
function validateAgreement(agreement: boolean): boolean {
  if (!agreement) {
    formErrors.agreement = '请阅读并同意用户协议和隐私政策'
    return false
  }
  
  formErrors.agreement = ''
  return true
}

// 发送验证码
async function sendVerificationCode() {
  if (!validatePhone(formData.phone)) return
  
  try {
    isSendingCode.value = true
    await authStore.sendPhoneVerificationCode(formData.phone)
    
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
    emit('register-error', error.message)
  } finally {
    isSendingCode.value = false
  }
}

// 手机注册
async function handleRegister() {
  // 重置表单错误
  Object.keys(formErrors).forEach(key => {
    // @ts-ignore
    formErrors[key] = ''
  })
  
  // 验证表单
  const isPhoneValid = validatePhone(formData.phone)
  const isCodeValid = validateCode(formData.code)
  const isNicknameValid = validateNickname(formData.nickname)
  const isPasswordValid = validatePassword(formData.password)
  const isConfirmPasswordValid = validateConfirmPassword(formData.password, formData.confirmPassword)
  const isAgreementValid = validateAgreement(formData.agreement)
  
  if (!isPhoneValid || !isCodeValid || !isNicknameValid || !isPasswordValid || !isConfirmPasswordValid || !isAgreementValid) {
    return
  }
  
  try {
    isLoading.value = true
    
    // 注册
    await authStore.registerPhone({
      phone: formData.phone,
      password: formData.password,
      confirmPassword: formData.confirmPassword,
      nickname: formData.nickname,
    })
    
    // 注册成功后验证手机号
    await authStore.verifyPhone(formData.code)
    
    // 显示注册成功提示
    registerSuccess.value = true
    
    // 发送注册成功事件
    emit('register-success')
    
  } catch (error: any) {
    emit('register-error', error.message)
  } finally {
    isLoading.value = false
  }
}

// 跳转到登录页
function goToLogin() {
  registerSuccess.value = false
  router.push({ path: '/login', query: { tab: 'login', type: 'phone' } })
}
</script>

<style scoped>
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

.agreement {
  display: flex;
  align-items: flex-start;
  margin-bottom: 15px;
  font-size: 14px;
}

.agreement input {
  margin-right: 8px;
  margin-top: 3px;
}

.agreement a {
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
  max-height: 80vh;
  overflow-y: auto;
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

.agreement-content {
  margin: 20px 0;
  max-height: 300px;
  overflow-y: auto;
  border: 1px solid #eee;
  padding: 15px;
  font-size: 14px;
  line-height: 1.5;
}

.success-modal {
  text-align: center;
  padding: 30px 20px;
}

.success-modal h3 {
  color: #28a745;
  margin-bottom: 20px;
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
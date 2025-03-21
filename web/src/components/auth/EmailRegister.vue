<template>
  <div>
    <!-- 当注册成功并发送验证邮件后显示 -->
    <div v-if="registrationStage === 'emailSent'" class="email-verification-info">
      <div class="success-icon">✓</div>
      <h2>验证邮件已发送</h2>
      <p>我们已向 <strong>{{ formData.email }}</strong> 发送了一封验证邮件。</p>
      <p>请查收邮件并点击验证链接完成注册。</p>
      
      <div class="tips">
        <p>没有收到邮件？</p>
        <ul>
          <li>请检查垃圾邮件或促销邮件文件夹</li>
          <li>确认您输入的邮箱地址正确</li>
          <li>等待几分钟后再次检查</li>
        </ul>
      </div>
      
      <div class="actions">
        <button @click="resendVerification" :disabled="resending" class="resend-btn">
          {{ resending ? '发送中...' : '重新发送验证邮件' }}
        </button>
        <button @click="resetForm" class="reset-btn">使用其他邮箱</button>
      </div>
    </div>
    
    <!-- 注册表单 -->
    <form v-else @submit.prevent="handleEmailRegister" class="auth-form">
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
          v-model="formData.email" 
          type="email" 
          placeholder="邮箱"
          :class="{ 'error': formErrors.email }"
        >
        <span v-if="formErrors.email" class="error-text">{{ formErrors.email }}</span>
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
        {{ isLoading ? '注册中...' : '邮箱注册' }}
      </button>
    </form>
  </div>
</template>

<script lang="ts" setup>
import { reactive, ref, defineEmits } from 'vue'
import axios from 'axios'

const emit = defineEmits<{
  (e: 'register-send-email'): void
  (e: 'register-success'): void
  (e: 'register-error', message: string): void
}>()

// 注册阶段状态: 'form' = 显示表单, 'emailSent' = 验证邮件已发送
const registrationStage = ref<'form' | 'emailSent'>('form')
const resending = ref(false) // 是否正在重发验证邮件

// 邮件模板

const baseURL = import.meta.env.VITE_BASE_URL

const verificationEmailTpl = `
  <h2>邮箱验证</h2>
  <p>您好，请点击以下链接验证您的邮箱：</p>
  <p><a href="${baseURL}/auth/verify-email?token={{.Token}}">验证邮箱</a></p>
  <p>如果链接无法点击，请复制以下地址到浏览器打开：</p>
  <p>${baseURL}/auth/verify-email?token={{.Token}}</p>
  <p>此链接将在24小时后过期。</p>
  `

const passwordResetEmailTpl = `
  <h2>密码重置</h2>
  <p>您好，请点击以下链接重置您的密码：</p>
  <p><a href="${baseURL}/auth/reset-password?token={{.Token}}">重置密码</a></p>
  <p>如果链接无法点击，请复制以下地址到浏览器打开：</p>
  <p>${baseURL}/auth/reset-password?token={{.Token}}</p>
  <p>此链接将在24小时后过期。如果您没有请求重置密码，请忽略此邮件。</p>
  `

const loginNotificationEmailTpl = `
  <h2>登录通知</h2>
  <p>您好，您的账号刚刚在新设备上登录：</p>
  <p>IP地址：{{.Ip}}</p>
  <p>时间：{{.Time}}</p>
  <p>如果这不是您本人的操作，请立即修改密码。</p>
  `


interface FormData {
  nickname: string
  email: string
  password: string
  confirmPassword: string
}

interface FormErrors {
  nickname?: string
  email?: string
  password?: string
  confirmPassword?: string
}

const isLoading = ref(false)
const formData = reactive<FormData>({
  nickname: '',
  email: '',
  password: '',
  confirmPassword: ''
})
const formErrors = reactive<FormErrors>({})

const validateForm = () => {
  let isValid = true
  
  // 清除之前的错误
  Object.keys(formErrors).forEach(key => delete formErrors[key as keyof FormErrors])
  
  if (!formData.nickname) {
    formErrors.nickname = '请输入昵称'
    isValid = false
  }
  
  if (!formData.email) {
    formErrors.email = '请输入邮箱'
    isValid = false
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
    formErrors.email = '请输入有效的邮箱地址'
    isValid = false
  }
  
  if (!formData.password) {
    formErrors.password = '请输入密码'
    isValid = false
  } else if (formData.password.length < 6) {
    formErrors.password = '密码长度至少6位'
    isValid = false
  }
  
  if (!formData.confirmPassword) {
    formErrors.confirmPassword = '请确认密码'
    isValid = false
  } else if (formData.password !== formData.confirmPassword) {
    formErrors.confirmPassword = '两次输入的密码不一致'
    isValid = false
  }
  
  return isValid
}

// 重新发送验证邮件
const resendVerification = async () => {
  if (!formData.email) {
    return
  }
  
  try {
    resending.value = true
    
    await axios.post('/auth/email/resend-verification', {
      email: formData.email,
      title: 'regist vextro.io',
      content: verificationEmailTpl
    })
    
    alert('验证邮件已重新发送，请查收')
  } catch (error: any) {
    alert(error.response?.data?.message || '重新发送验证邮件失败，请重试')
  } finally {
    resending.value = false
  }
}

// 重置表单，返回到注册状态
const resetForm = () => {
  registrationStage.value = 'form'
  formData.email = ''
  formData.password = ''
  formData.confirmPassword = ''
  // 保留昵称，方便用户使用
}

const handleEmailRegister = async () => {
  try {
    // 表单验证
    if (!validateForm()) return
    
    isLoading.value = true
    
    // 实际实现邮箱注册逻辑
    await axios.post('/auth/email/register', {
      nickname: formData.nickname,
      email: formData.email,
      password: formData.password,
      title: 'regist vextro.io',
      content: verificationEmailTpl
    })
    
    // 切换到邮件已发送状态
    registrationStage.value = 'emailSent'
    
    // 通知父组件
    emit('register-send-email')
  } catch (error: any) {
    // 注册失败，通知父组件
    emit('register-error', error.response?.data?.message || '邮箱注册失败，请重试')
  } finally {
    isLoading.value = false
  }
}
</script>

<style scoped>
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

/* 验证邮件发送成功页面样式 */
.email-verification-info {
  max-width: 500px;
  margin: 0 auto;
  padding: 20px;
  text-align: center;
  background-color: #f0f8ff;
  border-radius: 8px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.success-icon {
  width: 60px;
  height: 60px;
  margin: 0 auto 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background-color: #52c41a;
  color: white;
  font-size: 30px;
  font-weight: bold;
}

.tips {
  margin: 20px 0;
  text-align: left;
  padding: 15px;
  background-color: #fffbe6;
  border: 1px solid #ffe58f;
  border-radius: 4px;
}

.tips p {
  font-weight: bold;
  margin-bottom: 10px;
}

.tips ul {
  padding-left: 20px;
}

.tips li {
  margin-bottom: 5px;
}

.actions {
  display: flex;
  gap: 10px;
  justify-content: center;
  margin-top: 20px;
}

.resend-btn, .reset-btn {
  padding: 10px 15px;
  border: none;
  border-radius: 4px;
  font-size: 14px;
  cursor: pointer;
  transition: background-color 0.3s;
}

.resend-btn {
  background-color: #1890ff;
  color: white;
}

.resend-btn:hover {
  background-color: #40a9ff;
}

.resend-btn:disabled {
  background-color: #bfbfbf;
  cursor: not-allowed;
}

.reset-btn {
  background-color: #f0f0f0;
  color: #333;
}

.reset-btn:hover {
  background-color: #e0e0e0;
}
</style> 
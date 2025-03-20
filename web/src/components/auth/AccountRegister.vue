<template>
  <div>
    <!-- 注册方式切换 -->
    <div v-if="showRegisterTypeSelector" class="register-type-selector">
      <button 
        :class="['register-type-btn', { active: true }]" 
        @click="$emit('switch-type', 'account')"
      >
        账号注册
      </button>
      <button 
        :class="['register-type-btn', { active: false }]" 
        @click="$emit('switch-type', 'email')"
      >
        邮箱注册
      </button>
    </div>

    <!-- 账号注册表单 -->
    <form @submit.prevent="handleRegister" class="auth-form">
      <div class="form-item">
        <input 
          v-model="formData.username" 
          type="text" 
          placeholder="用户名"
          :class="{ 'error': formErrors.username }"
        >
        <span v-if="formErrors.username" class="error-text">{{ formErrors.username }}</span>
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
        {{ isLoading ? '注册中...' : '账号注册' }}
      </button>
    </form>
  </div>
</template>

<script lang="ts" setup>
import { reactive, ref, defineProps, defineEmits } from 'vue'
import { useAuthStore } from '@/stores/auth'

const props = defineProps<{
  showRegisterTypeSelector: boolean
}>()

const emit = defineEmits<{
  (e: 'switch-type', type: 'account' | 'email'): void
  (e: 'register-success'): void
  (e: 'register-error', message: string): void
}>()

interface FormData {
  username: string
  password: string
  confirmPassword: string
}

interface FormErrors {
  username?: string
  password?: string
  confirmPassword?: string
}

const authStore = useAuthStore()
const isLoading = ref(false)
const formData = reactive<FormData>({
  username: '',
  password: '',
  confirmPassword: ''
})
const formErrors = reactive<FormErrors>({})

const validateForm = () => {
  let isValid = true
  
  // 清除之前的错误
  Object.keys(formErrors).forEach(key => delete formErrors[key as keyof FormErrors])
  
  if (!formData.username) {
    formErrors.username = '请输入用户名'
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

const handleRegister = async () => {
  try {
    // 表单验证
    if (!validateForm()) return
    
    isLoading.value = true
    
    // 调用注册函数
    await authStore.registerAccount({
      username: formData.username,
      password: formData.password,
      confirmPassword: formData.confirmPassword
    })
    
    // 注册成功，通知父组件
    emit('register-success')
  } catch (error: any) {
    // 注册失败，通知父组件
    emit('register-error', error.message || '注册失败，请重试')
  } finally {
    isLoading.value = false
  }
}
</script>

<style scoped>
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
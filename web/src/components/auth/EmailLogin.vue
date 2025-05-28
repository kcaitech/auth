/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

<template>
  <div>
    <!-- 邮箱登录表单 -->
    <form @submit.prevent="handleEmailLogin" class="auth-form">
      <div class="form-item">
        <input 
          v-model="formData.email" 
          type="email" 
          :placeholder="$t('common.email')"
          :class="{ 'error': formErrors.email }"
        >
        <span v-if="formErrors.email" class="error-text">{{ formErrors.email }}</span>
      </div>
      
      <div class="form-item">
        <input 
          v-model="formData.password" 
          type="password" 
          :placeholder="$t('common.password')"
          :class="{ 'error': formErrors.password }"
        >
        <span v-if="formErrors.password" class="error-text">{{ formErrors.password }}</span>
      </div>

      <button type="submit" :disabled="isLoading" class="submit-btn">
        {{ isLoading ? $t('common.loading') : $t('auth.emailLogin') }}
      </button>
    </form>
  </div>
</template>

<script lang="ts" setup>
import { reactive, ref, defineEmits } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { serverApi } from '@/api/serverApi';

const emit = defineEmits<{
  (e: 'login-success'): void
  (e: 'login-error', message: string): void
}>()

interface FormData {
  email: string
  password: string
}

interface FormErrors {
  email?: string
  password?: string
}

const { t } = useI18n()
const isLoading = ref(false)
const formData = reactive<FormData>({
  email: '',
  password: ''
})
const formErrors = reactive<FormErrors>({})

const validateForm = () => {
  let isValid = true
  
  // 清除之前的错误
  Object.keys(formErrors).forEach(key => delete formErrors[key as keyof FormErrors])
  
  if (!formData.email) {
    formErrors.email = t('validation.required', { field: t('common.email') })
    isValid = false
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
    formErrors.email = t('validation.invalidEmail')
    isValid = false
  }
  
  if (!formData.password) {
    formErrors.password = t('validation.required', { field: t('common.password') })
    isValid = false
  }
  
  return isValid
}
const handleEmailLogin = async () => {
  try {
    // 表单验证
    if (!validateForm()) return
    
    isLoading.value = true
    
    // 实际实现邮箱登录逻辑
    const response = await serverApi.emailLogin(formData.email, formData.password)
    // const response = await axios.post('/email/login', {
    //   email: formData.email,
    //   password: formData.password
    // })

  } catch (error: any) {
    // 登录失败，通知父组件
    emit('login-error', error.response?.data?.message || t('errors.emailLoginFailed'))
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
</style> 
/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

<template>
  <div>
    <!-- 账号注册表单 -->
    <form @submit.prevent="handleRegister" class="auth-form">
      <div class="form-item">
        <input 
          v-model="formData.username" 
          type="text" 
          :placeholder="$t('common.username')"
          :class="{ 'error': formErrors.username }"
        >
        <span v-if="formErrors.username" class="error-text">{{ formErrors.username }}</span>
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

      <div class="form-item">
        <input 
          v-model="formData.confirmPassword" 
          type="password" 
          :placeholder="$t('common.confirmPassword')"
          :class="{ 'error': formErrors.confirmPassword }"
        >
        <span v-if="formErrors.confirmPassword" class="error-text">{{ formErrors.confirmPassword }}</span>
      </div>

      <button type="submit" :disabled="isLoading" class="submit-btn">
        {{ isLoading ? $t('common.registering') : $t('auth.accountRegister') }}
      </button>
    </form>
  </div>
</template>

<script lang="ts" setup>
import { serverApi } from '@/api/serverApi';
import { reactive, ref, defineEmits } from 'vue'
import { useI18n } from 'vue-i18n'

const emit = defineEmits<{
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

const { t } = useI18n()
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
    formErrors.username = t('validation.required', { field: t('common.username') })
    isValid = false
  }
  
  if (!formData.password) {
    formErrors.password = t('validation.required', { field: t('common.password') })
    isValid = false
  } else if (formData.password.length < 6) {
    formErrors.password = t('validation.passwordLength', { min: 6 })
    isValid = false
  }
  
  if (!formData.confirmPassword) {
    formErrors.confirmPassword = t('validation.required', { field: t('common.confirmPassword') })
    isValid = false
  } else if (formData.password !== formData.confirmPassword) {
    formErrors.confirmPassword = t('validation.passwordMismatch')
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
    await serverApi.registerAccount(formData.username, formData.password)

  } catch (error: any) {
    // 注册失败，通知父组件
    emit('register-error', error.message || t('errors.registerFailed'))
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
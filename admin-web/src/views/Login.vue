<template>
  <div class="login-container">
    <el-card class="login-card">
      <template #header>
        <div class="login-header">
          <h2>{{ $t('auth.welcome') }}</h2>
        </div>
      </template>
      
      <el-form
        ref="formRef"
        :model="loginForm"
        :rules="rules"
        label-position="top"
        @keyup.enter="handleLogin"
      >
        <el-form-item :label="$t('auth.username')" prop="username">
          <el-input
            v-model="loginForm.username"
            prefix-icon="el-icon-user"
            :placeholder="$t('auth.login_placeholder')"
          />
        </el-form-item>
        
        <el-form-item :label="$t('auth.password')" prop="password">
          <el-input
            v-model="loginForm.password"
            type="password"
            prefix-icon="el-icon-lock"
            :placeholder="$t('auth.password_placeholder')"
            show-password
          />
        </el-form-item>
        
        <el-form-item v-if="context.error">
          <el-alert
            :title="context.error"
            type="error"
            show-icon
            :closable="false"
          />
        </el-form-item>
        
        <el-form-item>
          <el-button
            type="primary"
            :loading="context.loading"
            @click="handleLogin"
            style="width: 100%"
          >
            {{ context.loading ? $t('auth.login_loading') : $t('auth.login') }}
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { context } from '@/context'
import { useI18n } from 'vue-i18n'
import type { FormInstance, FormRules } from 'element-plus'
import { serverApi } from '@/api'
import { isAuthenticated } from '@/utils'

const router = useRouter()
const formRef = ref<FormInstance>()
const { t } = useI18n()

// 表单数据
const loginForm = reactive({
  username: '',
  password: ''
})

// 表单验证规则
const rules = reactive<FormRules>({
  username: [
    { required: true, message: t('auth.error_username_required'), trigger: 'blur' }
  ],
  password: [
    { required: true, message: t('auth.error_password_required'), trigger: 'blur' }
  ]
})

// 如果已经登录，重定向到首页
onMounted(() => {
  if (isAuthenticated()) {
    router.push('/')
  }
})

// 登录处理
const handleLogin = () => {
  formRef.value?.validate((valid: boolean) => {
    if (valid) {
      serverApi.login({
        username: loginForm.username,
        password: loginForm.password
      }).then(() => {
        router.push('/')
      })
    }
  })
}

</script>

<style lang="scss" scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
  background-color: #f5f7fa;
}

.login-card {
  width: 400px;
  max-width: 90%;
  
  .login-header {
    text-align: center;
    
    h2 {
      margin: 0;
      font-size: 1.5rem;
      color: #409EFF;
    }
  }
}
</style> 
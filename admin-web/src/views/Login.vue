<template>
  <div class="login-container">
    <el-card class="login-card">
      <template #header>
        <div class="login-header">
          <h2>KC认证系统管理控制台</h2>
        </div>
      </template>
      
      <el-form
        ref="formRef"
        :model="loginForm"
        :rules="rules"
        label-position="top"
        @keyup.enter="handleLogin"
      >
        <el-form-item label="用户名" prop="username">
          <el-input
            v-model="loginForm.username"
            prefix-icon="el-icon-user"
            placeholder="请输入管理员用户名"
          />
        </el-form-item>
        
        <el-form-item label="密码" prop="password">
          <el-input
            v-model="loginForm.password"
            type="password"
            prefix-icon="el-icon-lock"
            placeholder="请输入密码"
            show-password
          />
        </el-form-item>
        
        <el-form-item v-if="authStore.error">
          <el-alert
            :title="authStore.error"
            type="error"
            show-icon
            :closable="false"
          />
        </el-form-item>
        
        <el-form-item>
          <el-button
            type="primary"
            :loading="authStore.loading"
            @click="handleLogin"
            style="width: 100%"
          >
            {{ authStore.loading ? '登录中...' : '登录' }}
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script lang="ts">
import { defineComponent, reactive, ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/store/auth'
import type { FormInstance, FormRules } from 'element-plus'

export default defineComponent({
  name: 'LoginView',
  setup() {
    const router = useRouter()
    const authStore = useAuthStore()
    const formRef = ref<FormInstance>()
    
    // 表单数据
    const loginForm = reactive({
      username: '',
      password: ''
    })
    
    // 表单验证规则
    const rules = reactive<FormRules>({
      username: [
        { required: true, message: '请输入用户名', trigger: 'blur' }
      ],
      password: [
        { required: true, message: '请输入密码', trigger: 'blur' }
      ]
    })
    
    // 如果已经登录，重定向到首页
    onMounted(() => {
      if (authStore.isAuthenticated) {
        router.push('/')
      }
    })
    
    // 登录处理
    const handleLogin = () => {
      formRef.value?.validate((valid: boolean) => {
        if (valid) {
          authStore.login({
            username: loginForm.username,
            password: loginForm.password
          })
        }
      })
    }
    
    return {
      formRef,
      loginForm,
      rules,
      authStore,
      handleLogin
    }
  }
})
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
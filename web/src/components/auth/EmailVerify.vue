/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

<template>
  <div class="email-verify-container">
    <div v-if="loading" class="verify-loading">
      <div class="spinner"></div>
      <p>{{ $t('emailVerify.loading') }}</p>
    </div>
    
    <div v-else-if="error" class="verify-error">
      <h1>{{ $t('emailVerify.verifyFailed') }}</h1>
      <p>{{ error }}</p>
      <div class="actions">
        <button @click="resendVerification" :disabled="resending">
          {{ resending ? $t('emailVerify.sending') : $t('emailVerify.resendVerification') }}
        </button>
        <button @click="goToRegister">{{ $t('emailVerify.register') }}</button>
        <button @click="goToLogin">{{ $t('emailVerify.backToLogin') }}</button>
      </div>
      
      <div v-if="resendSuccess" class="resend-success">
        <div class="success-icon-small">✓</div>
        {{ $t('emailVerify.resendSuccess') }}
      </div>
    </div>
    
    <div v-else-if="success" class="verify-success">
      <h1>{{ $t('emailVerify.verifySuccess') }}</h1>
      <p>{{ $t('emailVerify.emailVerified') }}</p>
      <div class="user-info" v-if="userInfo">
        <p>{{ $t('emailVerify.userId') }}: {{ userInfo.user_id }}</p>
        <p>{{ $t('emailVerify.nickname') }}: {{ userInfo.nickname }}</p>
      </div>
      <div class="actions">
        <button @click="goToHome">{{ $t('emailVerify.enterHome') }}</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useI18n } from 'vue-i18n';
import { verificationEmailTpl } from './emailtpl'
import axios from 'axios';

const route = useRoute();
const router = useRouter();
const { t } = useI18n();

const loading = ref(true);
const error = ref('');
const success = ref(false);
const resending = ref(false);
const verifiedEmail = ref('');
const resendSuccess = ref(false);

// 定义用户信息接口
interface UserInfo {
  user_id: string;
  token: string;
  nickname: string;
  [key: string]: any;
}

const userInfo = ref<UserInfo | null>(null);

// 验证邮箱
const verifyEmail = async (token: string) => {
  try {
    loading.value = true;
    
    const response = await axios.get(`/email/verify?token=${token}`, {
      headers: {
        'Content-Type': 'application/json',
      },
    });

    const data = response.data;

    if (response.status !== 200) {
      throw new Error(data.error || t('emailVerify.verifyFailed'));
    }
    
    // 验证成功，保存用户信息
    success.value = true;
    userInfo.value = data;
    
    // 更新用户状态
    if (data.token) {
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify({
        userId: data.user_id,
        nickname: data.nickname,
        avatar: data.avatar
      }));
    }
    
  } catch (err: any) {
    console.error('验证邮箱失败:', err);
    error.value = err.message || t('emailVerify.verifyFailed');
  } finally {
    loading.value = false;
  }
};

// 重新发送验证邮件
const resendVerification = async () => {
  if (!verifiedEmail.value) {
    error.value = t('emailVerify.cannotResend');
    return;
  }
  
  try {
    resending.value = true;
    resendSuccess.value = false;
    
    await axios.post('/email/resend-verification', {
      email: verifiedEmail.value,
      title: t('emailVerify.verifyFailed'),
      content: verificationEmailTpl
    });
    
    resendSuccess.value = true;
    
    setTimeout(() => {
      resendSuccess.value = false;
    }, 5000);
    
  } catch (err: any) {
    console.error('重新发送验证邮件失败:', err);
    error.value = err.response?.data?.message || t('emailVerify.verifyFailed');
  } finally {
    resending.value = false;
  }
};

// 跳转到注册页
const goToRegister = () => {
  router.push('/login?tab=register');
};

// 跳转到登录页
const goToLogin = () => {
  router.push('/login');
};

// 跳转到首页/仪表盘
const goToHome = () => {
  router.push('/dashboard');
};

onMounted(() => {
  const token = route.query.token as string;
  
  if (!token) {
    loading.value = false;
    error.value = t('emailVerify.invalidLink');
    return;
  }
  
  // 从路由中提取邮箱（如果有）
  verifiedEmail.value = route.query.email as string || '';
  
  // 开始验证
  verifyEmail(token);
});
</script>

<style scoped>
.email-verify-container {
  max-width: 500px;
  margin: 0 auto;
  padding: 40px 20px;
  text-align: center;
}

h1 {
  margin-bottom: 20px;
  color: #333;
}

.verify-loading, .verify-error, .verify-success {
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.verify-loading {
  display: flex;
  flex-direction: column;
  align-items: center;
}

.spinner {
  width: 40px;
  height: 40px;
  border: 4px solid #f3f3f3;
  border-top: 4px solid #3498db;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 15px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.verify-error {
  background-color: #fff0f0;
  border: 1px solid #ffcccc;
  color: #cc0000;
}

.verify-success {
  background-color: #f0fff0;
  border: 1px solid #ccffcc;
  color: #007700;
}

.user-info {
  margin: 20px 0;
  padding: 15px;
  background-color: #f9f9f9;
  border-radius: 4px;
  text-align: left;
}

.actions {
  margin-top: 20px;
  display: flex;
  gap: 10px;
  justify-content: center;
}

button {
  padding: 10px 15px;
  border: none;
  border-radius: 4px;
  background-color: #3498db;
  color: white;
  cursor: pointer;
  font-size: 14px;
  transition: background-color 0.3s;
}

button:hover {
  background-color: #2980b9;
}

button:disabled {
  background-color: #95a5a6;
  cursor: not-allowed;
}

/* 重发成功提示样式 */
.resend-success {
  display: flex;
  align-items: center;
  margin-top: 12px;
  padding: 8px 12px;
  background-color: #f6ffed;
  border: 1px solid #b7eb8f;
  border-radius: 4px;
  color: #52c41a;
  font-size: 14px;
  animation: fadeIn 0.3s ease-in-out;
}

.success-icon-small {
  width: 20px;
  height: 20px;
  margin-right: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background-color: #52c41a;
  color: white;
  font-size: 12px;
  font-weight: bold;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>


<template>
  <div class="email-verify-container">
    <div v-if="loading" class="verify-loading">
      <div class="spinner"></div>
      <p>正在验证您的邮箱...</p>
    </div>
    
    <div v-else-if="error" class="verify-error">
      <h1>验证失败</h1>
      <p>{{ error }}</p>
      <div class="actions">
        <button @click="resendVerification" :disabled="resending">
          {{ resending ? '发送中...' : '重新发送验证邮件' }}
        </button>
        <button @click="goToRegister">重新注册</button>
        <button @click="goToLogin">返回登录</button>
      </div>
    </div>
    
    <div v-else-if="success" class="verify-success">
      <h1>验证成功</h1>
      <p>您的邮箱已验证成功，账号已激活。</p>
      <div class="user-info" v-if="userInfo">
        <p>用户ID: {{ userInfo.user_id }}</p>
        <p>昵称: {{ userInfo.profile.nickname }}</p>
      </div>
      <div class="actions">
        <button @click="goToHome">进入首页</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { verificationEmailTpl } from './emailtpl'
import axios from 'axios';
const route = useRoute();
const router = useRouter();

const loading = ref(true);
const error = ref('');
const success = ref(false);
const resending = ref(false);
const verifiedEmail = ref('');

// 定义用户信息接口
interface UserInfo {
  user_id: string;
  token: string;
  profile: {
    nickname: string;
    [key: string]: any;
  };
  [key: string]: any;
}

const userInfo = ref<UserInfo | null>(null);

// 验证邮箱
const verifyEmail = async (token: string) => {
  try {
    loading.value = true;
    
    const response = await fetch(`/auth/email/verify?token=${token}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
    });

    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || '验证失败，请稍后重试');
    }
    
    // 验证成功，保存用户信息
    success.value = true;
    userInfo.value = data;
    
    // 更新用户状态
    if (data.token) {
      // 存储令牌到本地，实际项目中应该使用适当的存储方式
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify({
        userId: data.user_id,
        profile: data.profile
      }));
    }
    
  } catch (err: any) {
    console.error('验证邮箱失败:', err);
    error.value = err.message || '验证失败，请稍后重试';
  } finally {
    loading.value = false;
  }
};

// 重新发送验证邮件
const resendVerification = async () => {
  if (!verifiedEmail.value) {
    error.value = '无法重新发送验证邮件，请重新注册';
    return;
  }
  
  try {
    resending.value = true;
    
    // const response = await fetch('/auth/email/resend-verification', {
    //   method: 'POST',
    //   headers: {
    //     'Content-Type': 'application/json',
    //   },
    //   body: JSON.stringify({
    //     email: verifiedEmail.value,
    //     title: '邮箱验证',
    //     content: verificationEmailTpl
    //   })
    // });
    
    // const data = await response.json();

    await axios.post('/auth/email/resend-verification', {
      email: verifiedEmail.value,
      title: '邮箱验证',
      content: verificationEmailTpl
    })
    
    // if (!response.ok) {
    //   throw new Error(data.error || '重新发送失败，请稍后重试');
    // }
    
    alert('验证邮件已重新发送，请查收');
    
  } catch (err: any) {
    console.error('重新发送验证邮件失败:', err);
    error.value = err.message || '重新发送失败，请稍后重试';
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
    error.value = '验证链接无效，缺少验证令牌';
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
</style>


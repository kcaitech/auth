<template>
  <div class="dashboard-container">
    <header class="dashboard-header">
      <h1>{{ $t('dashboard.welcomeBack', { nickname: user?.nickname || $t('common.user') }) }}</h1>
      <button @click="logout" class="logout-btn">{{ $t('common.logout') }}</button>
    </header>
    
    <div class="dashboard-content">
      <div class="dashboard-card">
        <h2>{{ $t('dashboard.title') }}</h2>
        <p>{{ $t('dashboard.description') }}</p>
        <p>{{ $t('dashboard.loginSuccess') }}</p>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { onMounted, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

const authStore = useAuthStore()
const router = useRouter()
const { t } = useI18n()
const user = ref(authStore.currentUser)

onMounted(async () => {
  if (!user.value) {
    try {
      user.value = await authStore.fetchCurrentUser()
    } catch (error) {
      router.push('/login')
    }
  }
})

const logout = async () => {
  await authStore.logout()
  router.push('/login')
}
</script>

<style scoped>
.dashboard-container {
  max-width: 1000px;
  margin: 0 auto;
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
  padding-bottom: 20px;
  border-bottom: 1px solid #eee;
}

.logout-btn {
  padding: 8px 16px;
  background-color: #f56c6c;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.3s;
}

.logout-btn:hover {
  background-color: #e64242;
}

.dashboard-content {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 20px;
}

.dashboard-card {
  background: white;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.1);
}

h1 {
  font-size: 24px;
  color: #303133;
}

h2 {
  font-size: 18px;
  margin-bottom: 16px;
  color: #303133;
}

p {
  color: #606266;
  line-height: 1.6;
  margin-bottom: 12px;
}
</style> 
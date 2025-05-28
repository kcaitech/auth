<template>
  <div class="dashboard-container">
    <el-card class="dashboard-card">
      <template #header>
        <div class="card-header">
          <h2>{{ $t('dashboard.title') }}</h2>
          <el-button type="primary" size="small" @click="fetchStats">
            <i class="el-icon-refresh"></i> {{ $t('dashboard.refresh') }}
          </el-button>
        </div>
      </template>
      
      <el-skeleton :rows="4" animated v-if="loading" />
      
      <div v-else>
        <el-alert
          v-if="error"
          :title="error"
          type="error"
          show-icon
          :closable="false"
          style="margin-bottom: 20px;"
        />
        
        <div class="stats-grid">
          <!-- 总用户统计 -->
          <el-card shadow="hover" class="stat-card">
            <template #header>
              <div class="stat-header">
                <i class="el-icon-user"></i> {{ $t('dashboard.user_overview') }}
              </div>
            </template>
            <div class="stat-content">
              <div class="stat-item">
                <div class="stat-value primary">{{ stats.total_users }}</div>
                <div class="stat-label">{{ $t('dashboard.total_users') }}</div>
              </div>
              <div class="stat-item">
                <div class="stat-value success">{{ stats.active_users }}</div>
                <div class="stat-label">{{ $t('dashboard.active_users') }}</div>
              </div>
              <div class="stat-item">
                <div class="stat-value warning">{{ stats.inactive_users }}</div>
                <div class="stat-label">{{ $t('dashboard.inactive_users') }}</div>
              </div>
              <div class="stat-item">
                <div class="stat-value danger">{{ stats.banned_users }}</div>
                <div class="stat-label">{{ $t('dashboard.banned_users') }}</div>
              </div>
            </div>
          </el-card>
          
          <!-- 新增用户统计 -->
          <el-card shadow="hover" class="stat-card">
            <template #header>
              <div class="stat-header">
                <i class="el-icon-plus"></i> {{ $t('dashboard.new_users') }}
              </div>
            </template>
            <div class="stat-content">
              <div class="stat-item">
                <div class="stat-value success">{{ stats.new_today }}</div>
                <div class="stat-label">{{ $t('dashboard.new_today') }}</div>
              </div>
              <div class="stat-item">
                <div class="stat-value primary">{{ stats.new_this_week }}</div>
                <div class="stat-label">{{ $t('dashboard.new_this_week') }}</div>
              </div>
              <div class="stat-item">
                <div class="stat-value info">{{ stats.new_this_month }}</div>
                <div class="stat-label">{{ $t('dashboard.new_this_month') }}</div>
              </div>
            </div>
          </el-card>
          
          <!-- 登录统计 -->
          <el-card shadow="hover" class="stat-card">
            <template #header>
              <div class="stat-header">
                <i class="el-icon-key"></i> {{ $t('dashboard.login_stats') }}
              </div>
            </template>
            <div class="stat-content">
              <div class="stat-item">
                <div class="stat-value success">{{ stats.login_today }}</div>
                <div class="stat-label">{{ $t('dashboard.login_today') }}</div>
              </div>
              <div class="stat-item">
                <div class="stat-value primary">{{ stats.login_this_week }}</div>
                <div class="stat-label">{{ $t('dashboard.login_this_week') }}</div>
              </div>
              <div class="stat-item">
                <div class="stat-value info">{{ stats.login_this_month }}</div>
                <div class="stat-label">{{ $t('dashboard.login_this_month') }}</div>
              </div>
            </div>
          </el-card>
          
          <!-- 认证方式统计 -->
          <el-card shadow="hover" class="stat-card">
            <template #header>
              <div class="stat-header">
                <i class="el-icon-connection"></i> {{ $t('dashboard.auth_stats') }}
              </div>
            </template>
            <div class="stat-content">
              <div class="stat-item">
                <div class="stat-value info">{{ stats.verified_users }}</div>
                <div class="stat-label">{{ $t('dashboard.verified_users') }}</div>
              </div>
              <div class="stat-item">
                <div class="stat-value warning">{{ stats.unverified_users }}</div>
                <div class="stat-label">{{ $t('dashboard.unverified_users') }}</div>
              </div>
              <div class="stat-item">
                <div class="stat-value success">{{ stats.two_factor_enabled }}</div>
                <div class="stat-label">{{ $t('dashboard.two_factor_enabled') }}</div>
              </div>
              <div class="stat-item">
                <div class="stat-value primary">{{ stats.social_users }}</div>
                <div class="stat-label">{{ $t('dashboard.social_users') }}</div>
              </div>
            </div>
          </el-card>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { StatsData, serverApi as api } from '@/api/index'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
const loading = ref(true)
const error = ref('')

// 初始化统计数据
const stats = reactive<StatsData>({
  total_users: 0,
  active_users: 0,
  inactive_users: 0,
  locked_users: 0,
  banned_users: 0,
  new_today: 0,
  new_this_week: 0,
  new_this_month: 0,
  login_today: 0,
  login_this_week: 0,
  login_this_month: 0,
  verified_users: 0,
  unverified_users: 0,
  two_factor_enabled: 0,
  social_users: 0,
  local_users: 0
})

// 获取统计数据
const fetchStats = async () => {
  loading.value = true
  error.value = ''
  
  try {
    const data = await api.getStats()
    
    // 更新统计数据
    Object.assign(stats, data)
  } catch (e: any) {
    error.value = e.response?.data?.error || t('dashboard.load_failed')
    console.error(t('dashboard.get_stats_failed'), e)
  } finally {
    loading.value = false
  }
}

// 组件挂载时获取数据
onMounted(() => {
  fetchStats()
})

</script>

<style lang="scss" scoped>
.dashboard-container {
  .dashboard-card {
    margin-bottom: 20px;
  }
  
  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    
    h2 {
      margin: 0;
      font-size: 1.2rem;
      font-weight: 500;
    }
  }
  
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 20px;
  }
  
  .stat-card {
    .stat-header {
      display: flex;
      align-items: center;
      font-weight: 500;
      
      i {
        margin-right: 8px;
      }
    }
    
    .stat-content {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
    }
    
    .stat-item {
      text-align: center;
      flex: 1;
      min-width: 80px;
    }
    
    .stat-value {
      font-size: 1.5rem;
      font-weight: bold;
      margin-bottom: 4px;
      
      &.primary { color: #409EFF; }
      &.success { color: #67C23A; }
      &.warning { color: #E6A23C; }
      &.danger { color: #F56C6C; }
      &.info { color: #909399; }
    }
    
    .stat-label {
      font-size: 0.85rem;
      color: #606266;
    }
  }
}

// 响应式布局
@media (max-width: 768px) {
  .stats-grid {
    grid-template-columns: 1fr;
  }
}
</style> 
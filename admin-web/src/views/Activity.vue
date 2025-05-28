<template>
  <div class="activity-container">
    <el-card class="activity-card">
      <template #header>
        <div class="card-header">
          <h2>{{ $t('activity.title') }}</h2>
          <div class="filter-actions">
            <el-select v-model="daysFilter" :placeholder="$t('activity.time_range')" size="small">
              <el-option :label="$t('activity.last_7_days')" :value="7" />
              <el-option :label="$t('activity.last_30_days')" :value="30" />
              <el-option :label="$t('activity.last_90_days')" :value="90" />
            </el-select>
            <el-button type="primary" size="small" @click="fetchActivity">
              {{ $t('activity.load_data') }}
            </el-button>
          </div>
        </div>
      </template>
      
      <el-skeleton :rows="8" animated v-if="loading" />
      
      <div v-else>
        <el-alert
          v-if="error"
          :title="error"
          type="error"
          show-icon
          :closable="false"
          style="margin-bottom: 20px;"
        />
        
        <!-- 图表区域 -->
        <div v-if="activityData.length > 0" class="chart-container">
          <ActivityChart :data="activityData" />
        </div>
        
        <!-- 数据表格 -->
        <div class="table-container">
          <el-table
            :data="sortedActivityData"
            style="width: 100%"
            border
            stripe
            size="small"
          >
            <el-table-column prop="date" :label="$t('activity.date')" width="120" fixed />
            <el-table-column prop="new_users" :label="$t('activity.new_users')" width="100">
              <template #default="scope">
                <span class="highlight-value">{{ scope.row.new_users }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="active_users" :label="$t('activity.active_users')" width="100">
              <template #default="scope">
                <span class="highlight-value primary">{{ scope.row.active_users }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="login_attempts" :label="$t('activity.login_attempts')" width="100">
              <template #default="scope">
                <span class="highlight-value info">{{ scope.row.login_attempts }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="successful_auth" :label="$t('activity.successful_auth')" width="100">
              <template #default="scope">
                <span class="highlight-value success">{{ scope.row.successful_auth }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="failed_auth" :label="$t('activity.failed_auth')" width="100">
              <template #default="scope">
                <span class="highlight-value danger">{{ scope.row.failed_auth }}</span>
              </template>
            </el-table-column>
            <el-table-column :label="$t('activity.success_rate')" width="100">
              <template #default="scope">
                <span>{{ calculateSuccessRate(scope.row) }}%</span>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ActivityData, serverApi as api } from '@/api/index'
import { ElMessage } from 'element-plus'
import ActivityChart from './ActivityChart.vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
const loading = ref(true)
const error = ref('')
const activityData = ref<ActivityData[]>([])
const daysFilter = ref(30)

// 获取活跃数据
const fetchActivity = async () => {
  loading.value = true
  error.value = ''
  
  try {
    const data = await api.getActivity(daysFilter.value)
    activityData.value = data
  } catch (e: any) {
    error.value = e.response?.data?.error || t('activity.load_failed')
    ElMessage.error(error.value)
    console.error(t('activity.get_activity_failed'), e)
  } finally {
    loading.value = false
  }
}

// 计算成功率
const calculateSuccessRate = (row: ActivityData) => {
  if (row.login_attempts === 0) return '0'
  const rate = (row.successful_auth / row.login_attempts) * 100
  return rate.toFixed(2)
}

// 表格展示数据（倒序排列，最近日期在前）
const sortedActivityData = computed(() => {
  return [...activityData.value].reverse()
})

// 组件挂载时获取数据
onMounted(() => {
  fetchActivity()
})


</script>

<style lang="scss" scoped>
.activity-container {
  .activity-card {
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
    
    .filter-actions {
      display: flex;
      gap: 10px;
    }
  }
  
  .chart-container {
    margin-bottom: 20px;
    height: 400px;
  }
  
  .table-container {
    margin-top: 20px;
  }
  
  .highlight-value {
    font-weight: bold;
    
    &.primary { color: #409EFF; }
    &.success { color: #67C23A; }
    &.warning { color: #E6A23C; }
    &.danger { color: #F56C6C; }
    &.info { color: #909399; }
  }
}
</style> 
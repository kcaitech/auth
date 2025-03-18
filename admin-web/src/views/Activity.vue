<template>
  <div class="activity-container">
    <el-card class="activity-card">
      <template #header>
        <div class="card-header">
          <h2>用户活跃情况</h2>
          <div class="filter-actions">
            <el-select v-model="daysFilter" placeholder="时间范围" size="small">
              <el-option label="最近7天" :value="7" />
              <el-option label="最近30天" :value="30" />
              <el-option label="最近90天" :value="90" />
            </el-select>
            <el-button type="primary" size="small" @click="fetchActivity">
              加载数据
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
            <el-table-column prop="date" label="日期" width="120" fixed />
            <el-table-column prop="new_users" label="新用户" width="100">
              <template #default="scope">
                <span class="highlight-value">{{ scope.row.new_users }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="active_users" label="活跃用户" width="100">
              <template #default="scope">
                <span class="highlight-value primary">{{ scope.row.active_users }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="login_attempts" label="登录尝试" width="100">
              <template #default="scope">
                <span class="highlight-value info">{{ scope.row.login_attempts }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="successful_auth" label="成功认证" width="100">
              <template #default="scope">
                <span class="highlight-value success">{{ scope.row.successful_auth }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="failed_auth" label="失败认证" width="100">
              <template #default="scope">
                <span class="highlight-value danger">{{ scope.row.failed_auth }}</span>
              </template>
            </el-table-column>
            <el-table-column label="成功率" width="100">
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

<script lang="ts">
import { defineComponent, ref, computed, onMounted } from 'vue'
import api, { ActivityData } from '@/api'
import { ElMessage } from 'element-plus'
import ActivityChart from './ActivityChart.vue'

export default defineComponent({
  name: 'ActivityView',
  components: {
    ActivityChart
  },
  setup() {
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
        error.value = e.response?.data?.error || '加载活跃数据失败'
        ElMessage.error(error.value)
        console.error('获取活跃数据失败', e)
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
    
    return {
      loading,
      error,
      activityData,
      daysFilter,
      sortedActivityData,
      fetchActivity,
      calculateSuccessRate
    }
  }
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
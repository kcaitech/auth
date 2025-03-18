<template>
  <div class="chart-wrapper">
    <Line
      v-if="chartData"
      :data="chartData"
      :options="chartOptions"
    />
  </div>
</template>

<script lang="ts">
import { defineComponent, computed, PropType } from 'vue'
import { Line } from 'vue-chart-3'
import { Chart, registerables } from 'chart.js'
import { ActivityData } from '@/api'

// 注册Chart.js组件
Chart.register(...registerables)

export default defineComponent({
  name: 'ActivityChart',
  components: {
    Line
  },
  props: {
    data: {
      type: Array as PropType<ActivityData[]>,
      required: true
    }
  },
  setup(props) {
    // 处理图表数据
    const chartData = computed(() => {
      const dates = props.data.map(item => item.date)
      const newUsers = props.data.map(item => item.new_users)
      const activeUsers = props.data.map(item => item.active_users)
      const loginAttempts = props.data.map(item => item.login_attempts)
      
      return {
        labels: dates,
        datasets: [
          {
            label: '新用户',
            data: newUsers,
            borderColor: '#67C23A',
            backgroundColor: 'rgba(103, 194, 58, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4
          },
          {
            label: '活跃用户',
            data: activeUsers,
            borderColor: '#409EFF',
            backgroundColor: 'rgba(64, 158, 255, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4
          },
          {
            label: '登录尝试',
            data: loginAttempts,
            borderColor: '#E6A23C',
            backgroundColor: 'rgba(230, 162, 60, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4
          }
        ]
      }
    })
    
    // 图表配置选项
    const chartOptions = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'top' as const,
        },
        title: {
          display: true,
          text: '用户活跃趋势'
        },
        tooltip: {
          mode: 'index' as const,
          intersect: false
        }
      },
      scales: {
        x: {
          title: {
            display: true,
            text: '日期'
          }
        },
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: '数量'
          }
        }
      }
    }
    
    return {
      chartData,
      chartOptions
    }
  }
})
</script>

<style lang="scss" scoped>
.chart-wrapper {
  width: 100%;
  height: 100%;
}
</style> 
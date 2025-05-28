<template>
  <div class="chart-wrapper">
    <canvas ref="chartCanvas"></canvas>
  </div>
</template>

<script setup lang="ts">
import { PropType, onMounted, ref, watch } from 'vue'
import { Chart, registerables } from 'chart.js'
import { ActivityData } from '@/api'
import { useI18n } from 'vue-i18n'

// 注册所有Chart.js组件
Chart.register(...registerables)

const props = defineProps({
    data: {
      type: Array as PropType<ActivityData[]>,
      required: true
    }
  })

const { t } = useI18n()
const chartCanvas = ref<HTMLCanvasElement | null>(null)
let chart: Chart | null = null

const createChart = () => {
  if (!chartCanvas.value || !props.data || props.data.length === 0) return

  const ctx = chartCanvas.value.getContext('2d')
  if (!ctx) return

  const dates = props.data.map(item => item.date)
  const newUsers = props.data.map(item => item.new_users)
  const activeUsers = props.data.map(item => item.active_users)
  const loginAttempts = props.data.map(item => item.login_attempts)

  // 销毁之前的图表实例
  if (chart) {
    chart.destroy()
  }

  // 创建新的图表
  chart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: dates,
      datasets: [
        {
          label: t('activity.chart.new_users'),
          data: newUsers,
          backgroundColor: 'rgba(103, 194, 58, 0.1)',
          borderColor: '#67C23A',
          borderWidth: 2,
          fill: true,
          tension: 0.4
        },
        {
          label: t('activity.chart.active_users'),
          data: activeUsers,
          backgroundColor: 'rgba(64, 158, 255, 0.1)',
          borderColor: '#409EFF',
          borderWidth: 2,
          fill: true,
          tension: 0.4
        },
        {
          label: t('activity.chart.login_attempts'),
          data: loginAttempts,
          backgroundColor: 'rgba(230, 162, 60, 0.1)',
          borderColor: '#E6A23C',
          borderWidth: 2,
          fill: true,
          tension: 0.4
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'top'
        },
        title: {
          display: true,
          text: t('activity.chart.title')
        },
        tooltip: {
          mode: 'index',
          intersect: false
        }
      },
      scales: {
        x: {
          title: {
            display: true,
            text: t('activity.chart.date')
          }
        },
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: t('activity.chart.count')
          }
        }
      }
    }
  })
}

// 在组件挂载后创建图表
onMounted(() => {
  createChart()
})

// 当数据变化时更新图表
watch(() => props.data, () => {
  createChart()
}, { deep: true })

  
</script>

<style lang="scss" scoped>
.chart-wrapper {
  width: 100%;
  height: 100%;
}
</style> 
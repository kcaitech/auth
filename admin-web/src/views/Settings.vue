<template>
  <div class="settings-container">
    <el-card class="settings-card">
      <template #header>
        <div class="card-header">
          <h2>系统设置</h2>
        </div>
      </template>
      
      <el-empty 
        description="该功能暂未实现，敬请期待" 
        :image-size="200"
      >
        <template #image>
          <el-icon class="empty-icon"><Setting /></el-icon>
        </template>
      </el-empty>
    </el-card>
  </div>
</template>

<script lang="ts">
import { defineComponent } from 'vue'
import { Setting } from '@element-plus/icons-vue'

export default defineComponent({
  name: 'SettingsView',
  components: {
    Setting
  }
})
</script>

<style lang="scss" scoped>
.settings-container {
  .settings-card {
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
  
  .empty-icon {
    font-size: 100px;
    color: #909399;
  }
}
</style> 
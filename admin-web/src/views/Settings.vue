/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

<template>
  <div class="settings-container">
    <el-card class="settings-card">
      <template #header>
        <div class="card-header">
          <h2>{{ $t('settings.title') }}</h2>
        </div>
      </template>
      
      <el-empty 
        :description="$t('settings.not_implemented')" 
        :image-size="200"
      >
        <template #image>
          <el-icon class="empty-icon"><Setting /></el-icon>
        </template>
      </el-empty>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { Setting } from '@element-plus/icons-vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()


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
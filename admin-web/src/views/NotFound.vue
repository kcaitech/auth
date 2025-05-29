/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

<template>
  <div class="not-found-container">
    <div class="not-found-content">
      <h1>404</h1>
      <h2>{{ $t('notFound.title') }}</h2>
      <p>{{ $t('notFound.description') }}</p>
      <el-button type="primary" @click="$router.push('/')">{{ $t('notFound.back_to_home') }}</el-button>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { useI18n } from 'vue-i18n'

const $t = useI18n().t
</script>

<style scoped>
.not-found-container {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
  background-color: #f5f7fa;
}

.not-found-content {
  text-align: center;
  padding: 2rem;
}

h1 {
  font-size: 6rem;
  margin: 0;
  color: #409EFF;
}

h2 {
  margin-top: 0;
  font-size: 2rem;
  color: #303133;
}

p {
  margin-bottom: 2rem;
  color: #606266;
}
</style> 
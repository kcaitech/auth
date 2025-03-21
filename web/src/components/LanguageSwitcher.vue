<template>
  <div class="language-switcher">
    <select v-model="currentLocale" @change="switchLanguage" class="language-select">
      <option v-for="locale in locales" :key="locale.code" :value="locale.code">
        {{ locale.name }}
      </option>
    </select>
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { SUPPORTED_LOCALES, setLanguage } from '@/locales'

const { locale } = useI18n()
const currentLocale = ref(locale.value)
const locales = SUPPORTED_LOCALES

// 切换语言
const switchLanguage = () => {
  locale.value = currentLocale.value
  setLanguage(currentLocale.value)
}

// 组件挂载时获取当前语言
onMounted(() => {
  currentLocale.value = locale.value
})
</script>

<style scoped>
.language-switcher {
  margin: 0;
  padding: 0;
}

.language-select {
  padding: 5px 10px;
  border-radius: 4px;
  border: 1px solid #ddd;
  background-color: white;
  font-size: 0.9em;
  cursor: pointer;
  transition: all 0.2s ease;
  appearance: none;
  background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e");
  background-repeat: no-repeat;
  background-position: right 8px center;
  background-size: 12px;
  padding-right: 30px;
}

.language-select:hover {
  border-color: #1890ff;
}

.language-select:focus {
  outline: none;
  border-color: #1890ff;
  box-shadow: 0 0 0 2px rgba(24, 144, 255, 0.2);
}
</style> 
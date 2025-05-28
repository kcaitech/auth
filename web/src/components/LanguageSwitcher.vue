/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

<template>
  <div class="language-switcher">
    <div class="language-icon" @click="toggleDropdown">
      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="2" y1="12" x2="22" y2="12"></line>
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
      </svg>
    </div>
    <div v-if="isOpen" class="language-dropdown">
      <div v-for="locale in locales" 
           :key="locale.code" 
           class="language-option"
           :class="{ active: currentLocale === locale.code }"
           @click="selectLanguage(locale.code)">
        {{ locale.name }}
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { SUPPORTED_LOCALES, setLanguage } from '@/locales'

const { locale } = useI18n()
const currentLocale = ref(locale.value)
const locales = SUPPORTED_LOCALES
const isOpen = ref(false)

// 切换下拉菜单
const toggleDropdown = () => {
  isOpen.value = !isOpen.value
}

// 选择语言
const selectLanguage = (code: string) => {
  currentLocale.value = code
  locale.value = code
  setLanguage(code)
  isOpen.value = false
}

// 点击外部关闭下拉菜单
const handleClickOutside = (event: MouseEvent) => {
  const target = event.target as HTMLElement
  if (!target.closest('.language-switcher')) {
    isOpen.value = false
  }
}

onMounted(() => {
  currentLocale.value = locale.value
  document.addEventListener('click', handleClickOutside)
})

onUnmounted(() => {
  document.removeEventListener('click', handleClickOutside)
})
</script>

<style scoped>
.language-switcher {
  position: relative;
}

.language-icon {
  cursor: pointer;
  padding: 8px;
  color: #666;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
}

.language-icon svg {
  width: 24px;
  height: 24px;
}

.language-icon:hover {
  color: #1890ff;
}

.language-dropdown {
  position: absolute;
  top: 100%;
  right: 0;
  background: white;
  border-radius: 4px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
  min-width: 120px;
  margin-top: 4px;
}

.language-option {
  padding: 8px 16px;
  cursor: pointer;
  transition: all 0.2s;
}

.language-option:hover {
  background-color: #f5f5f5;
}

.language-option.active {
  color: #1890ff;
  background-color: #e6f7ff;
}
</style> 
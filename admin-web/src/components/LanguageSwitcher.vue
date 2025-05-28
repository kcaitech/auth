<template>
  <div class="language-switcher">
    <el-dropdown @command="switchLanguage">
      <span class="el-dropdown-link">
        {{ currentLocaleName }}
        <el-icon class="el-icon--right">
          <arrow-down />
        </el-icon>
      </span>
      <template #dropdown>
        <el-dropdown-menu>
          <el-dropdown-item 
            v-for="locale in locales" 
            :key="locale.code" 
            :command="locale.code"
            :class="{ 'is-active': currentLocale === locale.code }"
          >
            {{ locale.name }}
          </el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>
  </div>
</template>

<script lang="ts" setup>
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { SUPPORTED_LOCALES, setLanguage } from '@/lang'
import { ArrowDown } from '@element-plus/icons-vue'

const { locale } = useI18n()
const currentLocale = ref(locale.value)
const locales = SUPPORTED_LOCALES

// 当前语言名称
const currentLocaleName = computed(() => {
  const found = locales.find(l => l.code === currentLocale.value)
  return found ? found.name : ''
})

// 切换语言
const switchLanguage = (lang: string) => {
  locale.value = lang
  currentLocale.value = lang
  setLanguage(lang)
  
  // 刷新Element Plus的语言
  if (lang === 'zh-CN') {
    document.documentElement.lang = 'zh-CN'
  } else {
    document.documentElement.lang = 'en'
  }
}

// 组件挂载时获取当前语言
onMounted(() => {
  currentLocale.value = locale.value
})
</script>

<style scoped>
.language-switcher {
  display: inline-flex;
  align-items: center;
}

.el-dropdown-link {
  cursor: pointer;
  display: flex;
  align-items: center;
  color: #606266;
}

.is-active {
  color: #409EFF;
  font-weight: bold;
}
</style> 
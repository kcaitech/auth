import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import en from 'element-plus/es/locale/lang/en'
import App from './App.vue'
import router from './router'
import i18n, { getPreferredLanguage } from './lang'

// 创建应用实例
const app = createApp(App)

// 根据当前语言设置Element Plus的语言
const currentLang = getPreferredLanguage()
const elementLocale = currentLang === 'zh-CN' ? zhCn : en

// 使用插件
app.use(createPinia())
app.use(router)
app.use(ElementPlus, {
  locale: elementLocale
})
app.use(i18n)

// 挂载应用
app.mount('#app') 
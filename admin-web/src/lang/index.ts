import { createI18n } from 'vue-i18n'
import zhCN from './zh-CN'
import enUS from './en-US'

// 支持的语言列表
export const SUPPORTED_LOCALES = [
  {
    code: 'en-US',
    name: 'English',
  },
  {
    code: 'zh-CN',
    name: '中文',
  }
]

// 获取首选语言
export function getPreferredLanguage(): string {
  // 优先从本地存储获取
  const storedLang = localStorage.getItem('adminLanguage')
  if (storedLang && SUPPORTED_LOCALES.some(locale => locale.code === storedLang)) {
    return storedLang
  }

  // 然后从浏览器语言获取
  const browserLang = navigator.language
  const matchedLocale = SUPPORTED_LOCALES.find(locale => 
    browserLang.toLowerCase().includes(locale.code.toLowerCase())
  )

  return matchedLocale ? matchedLocale.code : 'zh-CN' // 默认中文
}

// 设置语言
export function setLanguage(lang: string) {
  localStorage.setItem('adminLanguage', lang)
  document.documentElement.setAttribute('lang', lang)
}

// 创建i18n实例
const i18n = createI18n({
  legacy: false, // 使用Composition API模式
  locale: getPreferredLanguage(),
  fallbackLocale: 'zh-CN',
  messages: {
    'en-US': enUS,
    'zh-CN': zhCN,
  },
})

export default i18n 
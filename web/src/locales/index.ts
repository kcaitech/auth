/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

import { createI18n } from 'vue-i18n'
import enUS from './en-US'
import zhCN from './zh-CN'

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
  const storedLang = localStorage.getItem('language')
  if (storedLang && SUPPORTED_LOCALES.some(locale => locale.code === storedLang)) {
    return storedLang
  }

  // 然后从浏览器语言获取
  const browserLang = navigator.language
  const matchedLocale = SUPPORTED_LOCALES.find(locale => 
    browserLang.toLowerCase().includes(locale.code.toLowerCase())
  )

  return matchedLocale ? matchedLocale.code : 'en-US' // 默认英文
}

// 设置语言
export function setLanguage(lang: string) {
  localStorage.setItem('language', lang)
  document.documentElement.setAttribute('lang', lang)
}

// 创建i18n实例
const i18n = createI18n({
  legacy: false, // 使用Composition API模式
  locale: getPreferredLanguage(),
  fallbackLocale: 'en-US',
  warnHtmlMessage: false,
  messages: {
    'en-US': enUS,
    'zh-CN': zhCN,
  },
})

export default i18n 
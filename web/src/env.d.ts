/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL: string
  // 更多环境变量...
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
} 

/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/ban-types
  const component: DefineComponent<{}, {}, any>
  export default component
}

// Vite环境变量类型声明
interface ImportMeta {
  readonly env: {
    readonly VITE_API_BASE_URL: string
    readonly MODE: string
    readonly DEV: boolean
    readonly PROD: boolean
    readonly SSR: boolean
    [key: string]: any
  }
} 
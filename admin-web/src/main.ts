import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import App from './App.vue'
import router from './router'

// 创建应用实例
const app = createApp(App)

// 使用插件
app.use(createPinia())
app.use(router)
app.use(ElementPlus, {
  locale: zhCn
})

// 挂载应用
app.mount('#app') 
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import './styles/theme.css'
import { useThemeStore } from './stores/theme'

const bootstrap = async () => {
  console.log('[🚀 main.ts] 开始启动应用')

  // 等待 Tauri API 加载完成（如果在 Tauri 环境）
  if (typeof window !== 'undefined' && (window as any).__TAURI__) {
    console.log('[🚀 main.ts] Tauri API 已加载')
  } else if (typeof window !== 'undefined') {
    console.log('[🚀 main.ts] 等待 Tauri API 加载...')
    // 等待一段时间确保 Tauri API 初始化
    await new Promise((resolve) => setTimeout(resolve, 100))
    console.log('[🚀 main.ts] Tauri 初始化检查完成')
  }

  const app = createApp(App)
  const pinia = createPinia()
  app.use(pinia)

  console.log('[🚀 main.ts] 创建 Pinia store')
  const themeStore = useThemeStore(pinia)

  console.log('[🚀 main.ts] 调用 themeStore.initialize()')
  await themeStore.initialize()
  console.log('[🚀 main.ts] themeStore.initialize() 完成')

  console.log('[🚀 main.ts] 挂载应用到 #app')
  app.mount('#app')
  console.log('[🚀 main.ts] 应用挂载完成')
}

console.log('[🚀 main.ts] 模块加载开始')
void bootstrap()
console.log('[🚀 main.ts] bootstrap() 已调用')

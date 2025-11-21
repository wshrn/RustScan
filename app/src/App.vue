<template>
  <div class="h-screen w-screen overflow-hidden" :class="{ dark: isDark }">
    <div class="app-shell h-full w-full">
      <div class="app-shell__glow app-shell__glow--primary" />
      <div class="app-shell__glow app-shell__glow--secondary" />
      <div class="flex h-full flex-col">
        <TitleBar />
        <main class="flex-1 overflow-auto p-8">
          <section class="app-panel">
            <div class="panel-header">
              <span class="panel-chip">RustScan Desktop</span>
              <h1 class="panel-title">快速端口扫描</h1>
              <p class="panel-subtitle">
                使用 Tauri 与 Vue3 构建的全新图形化客户端，开箱即用，支持主题切换与自定义标题栏。
              </p>
            </div>
            <div class="panel-section">
              <div class="panel-section__title-wrap">
                <span class="panel-section__title">运行状态</span>
                <span class="panel-section__hint">实时同步窗口控制与主题状态</span>
              </div>
              <div class="status-grid">
                <article class="status-card status-card--ok">
                  <div class="status-card__icon">
                    <span class="status-card__beam" />
                    <span class="status-card__dot" />
                  </div>
                  <div>
                    <p class="status-card__label">界面就绪</p>
                    <p class="status-card__message">
                      窗口装饰与拖拽已启用，点击右上角按钮体验最小化、最大化与关闭。
                    </p>
                    <p class="status-card__detail">当前主题：{{ themeLabel }}</p>
                  </div>
                </article>
                <article class="status-card">
                  <div class="status-card__icon">
                    <span class="status-card__beam" />
                    <span class="status-card__dot" />
                  </div>
                  <div>
                    <p class="status-card__label">环境准备</p>
                    <p class="status-card__message">
                      前端样式由 TailwindCSS 驱动，后端通过 Tauri 完成离线密钥验证与配置管理。
                    </p>
                    <p class="status-card__detail">启动日志写入浏览器控制台。</p>
                  </div>
                </article>
              </div>
            </div>
          </section>
        </main>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import TitleBar from './components/TitleBar.vue'
import { useThemeStore } from './stores/theme'

const themeStore = useThemeStore()
const { isDark, theme } = storeToRefs(themeStore)

const themeLabel = computed(() => {
  switch (theme.value) {
    case 'dark':
      return '深色模式'
    case 'light':
      return '浅色模式'
    default:
      return '跟随系统'
  }
})
</script>

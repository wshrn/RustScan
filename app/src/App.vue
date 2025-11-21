<template>
  <div class="app-shell" :class="{ dark: isDark }">
    <div class="app-shell__glow app-shell__glow--primary" aria-hidden="true" />
    <div class="app-shell__glow app-shell__glow--secondary" aria-hidden="true" />
    <TitleBar />
    <main class="p-6 sm:p-10">
      <section class="app-panel">
        <header class="panel-header">
          <span class="panel-chip">RustScan GUI</span>
          <h1 class="panel-title">更直观的端口扫描体验</h1>
          <p class="panel-subtitle">
            使用全新的图形化界面快速配置扫描、查看状态并切换主题。核心扫描引擎保持 Rust 版性能，界面层以 Vue + Tauri 提供桌面体验。
          </p>
        </header>

        <div class="panel-section status-grid">
          <div class="status-card status-card--ok">
            <div class="status-card__icon">
              <span class="status-card__beam" />
              <span class="status-card__dot" />
            </div>
            <div>
              <p class="status-card__label">扫描引擎</p>
              <p class="status-card__message">核心功能准备就绪</p>
              <p class="status-card__detail">CLI 逻辑可通过 Tauri 后端调用</p>
            </div>
          </div>
          <div class="status-card">
            <div class="status-card__icon">
              <span class="status-card__beam" />
              <span class="status-card__dot" />
            </div>
            <div>
              <p class="status-card__label">主题</p>
              <p class="status-card__message">{{ themeLabel }}</p>
              <p class="status-card__detail">点击右上角按钮在明暗/自动之间切换</p>
            </div>
          </div>
        </div>

        <footer class="panel-footer">
          <dl class="panel-meta">
            <div>
              <dt>模式</dt>
              <dd>{{ theme }}</dd>
            </div>
            <div>
              <dt>系统偏好</dt>
              <dd>{{ systemTheme }}</dd>
            </div>
            <div>
              <dt>当前配色</dt>
              <dd>{{ isDark ? '深色' : '浅色' }}</dd>
            </div>
          </dl>
          <div class="panel-action">
            <button class="btn-primary" type="button" @click="cycleTheme">
              切换主题
            </button>
          </div>
        </footer>
      </section>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import TitleBar from './components/TitleBar.vue'
import { useThemeStore } from './stores/theme'

const themeStore = useThemeStore()
const { isDark, theme, systemTheme } = storeToRefs(themeStore)

const themeLabel = computed(() => {
  if (theme.value === 'auto') {
    return `跟随系统（${systemTheme.value}）`
  }
  return theme.value === 'dark' ? '深色模式' : '浅色模式'
})

const cycleTheme = () => {
  const modes: Array<'light' | 'dark' | 'auto'> = ['light', 'dark', 'auto']
  const idx = modes.indexOf(theme.value)
  const next = modes[(idx + 1) % modes.length]
  void themeStore.setTheme(next)
}
</script>

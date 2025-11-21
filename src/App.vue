<template>
  <div class="app-shell min-h-screen bg-[var(--app-surface-bg)] text-slate-900 dark:text-slate-100">
    <div class="app-shell__glow app-shell__glow--primary" aria-hidden="true" />
    <div class="app-shell__glow app-shell__glow--secondary" aria-hidden="true" />
    <TitleBar />
    <main class="p-8">
      <section class="app-panel">
        <div class="panel-header">
          <span class="panel-chip">Desktop UI</span>
          <h1 class="panel-title">RustScan 图形化控制台</h1>
          <p class="panel-subtitle">现在应用启动后直接进入桌面界面，支持主题切换与自定义标题栏。</p>
        </div>
        <div class="panel-section panel-section--mirrors">
          <div class="panel-section__title-wrap">
            <span class="panel-section__title">镜像源</span>
            <span class="panel-section__hint">示例下拉组件</span>
          </div>
          <div class="mirror-select">
            <span :id="labelId" class="mirror-select__label">下载镜像</span>
            <MirrorSelectDropdown
              v-model="mirror"
              :options="mirrors"
              :label-id="labelId"
            />
            <p class="mirror-select__note">选项仅作展示，可根据需求填充真实镜像列表。</p>
          </div>
        </div>
        <div class="panel-section">
          <div class="panel-section__title-wrap">
            <span class="panel-section__title">状态预览</span>
            <span class="panel-section__hint">夜间模式支持发光效果</span>
          </div>
          <div class="status-grid">
            <article class="status-card status-card--ok">
              <div class="status-card__icon">
                <span class="status-card__beam" />
                <span class="status-card__dot" />
              </div>
              <div>
                <p class="status-card__label">UI 准备就绪</p>
                <p class="status-card__message">组件、主题与标题栏均已加载。
                </p>
                <p class="status-card__detail">当前镜像：{{ mirror || '未选择' }}</p>
              </div>
            </article>
            <article class="status-card status-card--error">
              <div class="status-card__icon">
                <span class="status-card__beam" />
                <span class="status-card__dot" />
              </div>
              <div>
                <p class="status-card__label">后端配置</p>
                <p class="status-card__message">请确保环境变量 keyzhigongfile 已指向离线授权文件。</p>
                <p class="status-card__detail">主题可通过 ZHIGONG_TOOLBOX_THEME 覆盖。</p>
              </div>
            </article>
          </div>
        </div>
        <footer class="panel-footer">
          <dl class="panel-meta">
            <div>
              <dt>主题模式</dt>
              <dd>{{ themeModeLabel }}</dd>
            </div>
            <div>
              <dt>系统主题</dt>
              <dd>{{ systemTheme }}</dd>
            </div>
            <div>
              <dt>当前镜像</dt>
              <dd>{{ mirror || '未选择' }}</dd>
            </div>
          </dl>
          <div class="panel-action">
            <button type="button" class="btn-primary" @click="cycleTheme">切换主题</button>
          </div>
        </footer>
      </section>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import TitleBar from './components/TitleBar.vue'
import MirrorSelectDropdown from './components/MirrorSelectDropdown.vue'
import { useThemeStore } from './stores/theme'

const mirror = ref('')
const mirrors = ref([
  { label: '主镜像（示例）', value: 'https://mirror.example.com' },
  { label: '备用镜像 A', value: 'https://backup-a.example.com' },
  { label: '备用镜像 B', value: 'https://backup-b.example.com' },
])

const labelId = `mirror-label-${Math.random().toString(36).slice(2, 8)}`

const themeStore = useThemeStore()
const { theme, systemTheme } = storeToRefs(themeStore)

const themeModeLabel = computed(() => {
  switch (theme.value) {
    case 'light':
      return '浅色'
    case 'dark':
      return '深色'
    default:
      return '跟随系统'
  }
})

const cycleTheme = () => {
  const modes: Array<'light' | 'dark' | 'auto'> = ['light', 'dark', 'auto']
  const nextIndex = (modes.indexOf(theme.value) + 1) % modes.length
  void themeStore.setTheme(modes[nextIndex])
}
</script>

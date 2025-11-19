<template>
  <div class="app-shell">
    <span class="app-shell__glow app-shell__glow--primary" aria-hidden="true" />
    <span class="app-shell__glow app-shell__glow--secondary" aria-hidden="true" />
    <TitleBar />
    <main class="app-panel">
      <header class="panel-header">
        <div>
          <h1 class="panel-title">运行时环境配置助手</h1>
          <p class="panel-subtitle">一键侦测并智能修复运行时环境，快速接入本地高可用镜像源。</p>
        </div>
      </header>

      <section class="panel-section">
        <h2 class="panel-section__title">状态诊断</h2>
        <div class="status-grid">
          <article
            v-for="item in statusLines"
            :key="item.label"
            class="status-card"
            :class="item.status.ok ? 'status-card--ok' : 'status-card--error'"
          >
            <div class="status-card__icon" aria-hidden="true">
              <span class="status-card__beam" />
              <span class="status-card__dot" />
            </div>
            <div>
              <p class="status-card__label">{{ item.label }}</p>
              <p class="status-card__message">{{ item.status.message }}</p>
              <p v-if="item.status.detail" class="status-card__detail">{{ item.status.detail }}</p>
            </div>
          </article>
        </div>
      </section>

      <section class="panel-section panel-section--mirrors">
        <div class="panel-section__title-wrap">
          <h2 class="panel-section__title">镜像智能切换</h2>
          <p class="panel-section__hint">自适配可信镜像，保持依赖分发稳定。</p>
        </div>
        <div class="mirror-select">
          <label :id="mirrorSelectLabelId" class="mirror-select__label">选择默认包管理镜像源</label>
          <MirrorSelectDropdown
            v-model="selectedMirror"
            :options="mirrorOptions"
            :disabled="initializing"
            :label-id="mirrorSelectLabelId"
          />
          <p class="mirror-select__note">系统将写入全局配置并同步可信主机列表。</p>
        </div>
      </section>

      <footer class="panel-footer">
        <dl class="panel-meta">
          <div>
            <dt>当前运行时路径</dt>
            <dd>{{ status?.pythonPath ?? '未检测到' }}</dd>
          </div>
          <div>
            <dt>可执行脚本目录</dt>
            <dd>{{ status?.scriptsPath ?? '未检测到' }}</dd>
          </div>
          <div>
            <dt>当前镜像</dt>
            <dd>{{ status?.pipMirrorConfigured.currentMirror ?? '未检测到' }}</dd>
          </div>
        </dl>
        <button
          class="btn-primary panel-action"
          :disabled="initializing || loading"
          @click="handleInitialize"
        >
          <span v-if="initializing" class="panel-action__loading">
            <svg class="panel-action__spinner" viewBox="0 0 24 24" fill="none">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
            </svg>
            <span>正在初始化...</span>
          </span>
          <span v-else>开始初始化</span>
        </button>
      </footer>

      <Transition name="dialog">
        <div
          v-if="dialog.visible"
          class="dialog-backdrop"
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="dialog-title"
        >
          <article class="dialog-panel" :class="dialog.type">
            <header class="dialog-panel__header">
              <h3 id="dialog-title" class="dialog-panel__title">{{ dialog.title }}</h3>
              <button class="dialog-panel__close" type="button" @click="closeDialog" aria-label="关闭提示">
                <svg class="dialog-panel__close-icon" viewBox="0 0 20 20" fill="none" aria-hidden="true">
                  <path d="M6 6l8 8M14 6l-8 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
                </svg>
              </button>
            </header>
            <p class="dialog-panel__message">{{ dialog.message }}</p>
            <footer class="dialog-panel__footer">
              <button class="btn-primary dialog-panel__action" type="button" @click="closeDialog">
                我知道了
              </button>
            </footer>
          </article>
        </div>
      </Transition>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import MirrorSelectDropdown from './components/MirrorSelectDropdown.vue'
import TitleBar from './components/TitleBar.vue'
import { fetchPythonEnvStatus, initializePythonEnvironment, type PythonEnvStatus } from './services/pythonEnv'

const status = ref<PythonEnvStatus | null>(null)
const loading = ref(true)
const initializing = ref(false)
const selectedMirror = ref('https://pypi.tuna.tsinghua.edu.cn/simple')
const dialog = reactive({
  visible: false,
  title: '',
  message: '',
  type: 'info' as 'success' | 'error' | 'info' | 'warning',
})

const mirrorSelectLabelId = 'mirror-select-label'

const mirrorOptions = computed(() => status.value?.mirrorCandidates ?? [
  {
    label: '清华大学 TUNA',
    value: 'https://pypi.tuna.tsinghua.edu.cn/simple',
    trustedHosts: ['pypi.tuna.tsinghua.edu.cn'],
  },
])

const statusLines = computed(() => {
  if (!status.value) {
    return []
  }
  return [
    { label: '当前目录检测', status: status.value.pythonPresent },
    { label: '运行时环境变量', status: status.value.pythonEnvVar },
    { label: 'PATH 中的运行时目录', status: status.value.pathConfigured },
    { label: 'PATH 中的脚本目录', status: status.value.scriptsConfigured },
    { label: '镜像配置', status: status.value.pipMirrorConfigured },
  ]
})

const openDialog = (item: { title: string; message: string; type?: 'success' | 'error' | 'info' | 'warning' }) => {
  dialog.title = item.title
  dialog.message = item.message
  dialog.type = item.type ?? 'info'
  dialog.visible = true
}

const closeDialog = () => {
  dialog.visible = false
}

const synchronizeMirrorSelection = () => {
  const current = status.value?.pipMirrorConfigured.currentMirror
  if (current && mirrorOptions.value.some((item) => item.value === current)) {
    selectedMirror.value = current
  } else if (mirrorOptions.value.length > 0) {
    selectedMirror.value = mirrorOptions.value[0].value
  }
}

const loadStatus = async () => {
  loading.value = true
  try {
    status.value = await fetchPythonEnvStatus()
    synchronizeMirrorSelection()
  } catch (error) {
    console.error(error)
    openDialog({
      title: '状态读取失败',
      message: error instanceof Error ? error.message : String(error),
      type: 'error',
    })
  } finally {
    loading.value = false
  }
}

const handleInitialize = async () => {
  if (!status.value) {
    return
  }
  initializing.value = true
  try {
    status.value = await initializePythonEnvironment({ mirror: selectedMirror.value })
    synchronizeMirrorSelection()
    openDialog({
      title: '初始化完成',
      message: '运行时环境变量与国内镜像已配置。',
      type: 'success',
    })
  } catch (error) {
    console.error(error)
    openDialog({
      title: '初始化失败',
      message: error instanceof Error ? error.message : String(error),
      type: 'error',
    })
  } finally {
    initializing.value = false
  }
}

onMounted(async () => {
  await loadStatus()
})
</script>

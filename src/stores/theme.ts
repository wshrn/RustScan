import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { isTauri } from '../utils/runtime'

type ThemeMode = 'light' | 'dark' | 'auto'
type SystemTheme = 'light' | 'dark'

const LOCAL_THEME_KEY = 'theme'

export const useThemeStore = defineStore('theme', () => {
  const theme = ref<ThemeMode>('auto')
  const systemTheme = ref<SystemTheme>('light')

  const isDark = computed(() => {
    if (theme.value === 'auto') {
      return systemTheme.value === 'dark'
    }
    return theme.value === 'dark'
  })

  const updateMetaThemeColor = () => {
    if (typeof document === 'undefined') {
      return
    }
    const meta = document.querySelector("meta[name='theme-color']") as HTMLMetaElement | null
    if (!meta) {
      return
    }
    meta.content = isDark.value ? '#111827' : '#f2f2f7'
  }

  const applyTheme = () => {
    if (typeof document === 'undefined') {
      return
    }
    const root = document.documentElement
    const body = document.body

    if (isDark.value) {
      root.classList.add('dark')
      root.classList.remove('light')
      body.classList.add('dark')
      body.classList.remove('light')
      root.style.colorScheme = 'dark'
      body.style.backgroundColor = '#111827'
    } else {
      root.classList.add('light')
      root.classList.remove('dark')
      body.classList.add('light')
      body.classList.remove('dark')
      root.style.colorScheme = 'light'
      body.style.backgroundColor = '#f2f2f7'
    }

    updateMetaThemeColor()
  }

  const detectSystemTheme = () => {
    if (typeof window === 'undefined') {
      return
    }
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    systemTheme.value = mediaQuery.matches ? 'dark' : 'light'

    mediaQuery.addEventListener('change', (event) => {
      systemTheme.value = event.matches ? 'dark' : 'light'
      if (theme.value === 'auto') {
        applyTheme()
      }
    })
  }

  const fetchInitialTheme = async () => {
    if (!isTauri()) {
      const stored = typeof window !== 'undefined' ? window.localStorage.getItem(LOCAL_THEME_KEY) : null
      if (stored === 'light' || stored === 'dark' || stored === 'auto') {
        theme.value = stored
      }
      applyTheme()
      return
    }

    try {
      const value = await invoke<ThemeMode>('tool_read_theme')
      theme.value = value
    } catch (error) {
      console.warn('读取主题失败，使用自动模式', error)
      theme.value = 'auto'
    }
    applyTheme()
  }

  const initialize = async () => {
    if (typeof window === 'undefined') {
      return
    }
    detectSystemTheme()
    await fetchInitialTheme()
  }

  const persistTheme = async (next: ThemeMode) => {
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(LOCAL_THEME_KEY, next)
    }

    if (!isTauri()) {
      return
    }

    try {
      await invoke('save_config', { key: 'theme', value: next })
    } catch (error) {
      console.error('保存主题失败', error)
    }

    try {
      await invoke('sync_theme_env', { value: next })
    } catch (error) {
      console.error('同步主题环境变量失败', error)
    }
  }

  const setTheme = async (next: ThemeMode) => {
    theme.value = next
    applyTheme()

    await persistTheme(next)
  }

  return {
    theme,
    systemTheme,
    isDark,
    initialize,
    setTheme,
  }
})

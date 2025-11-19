export const isTauri = (): boolean => {
  if (typeof window === 'undefined') {
    return false
  }
  return Boolean((window as typeof window & { __TAURI__?: unknown }).__TAURI__)
}

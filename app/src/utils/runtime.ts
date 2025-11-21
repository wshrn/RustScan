export const isTauri = () => {
  if (typeof window === 'undefined') {
    return false
  }
  return Boolean((window as unknown as { __TAURI__?: unknown }).__TAURI__)
}

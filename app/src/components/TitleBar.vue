<template>
  <header
    class="title-bar"
    data-tauri-drag-region
    @mousedown="startDragging"
  >
    <div class="title-bar__brand pointer-events-none">
      <span class="title-bar__logo" aria-hidden="true">
        <span class="title-bar__logo-core" />
      </span>
      <div class="title-bar__text">
        <strong>Unified Suite</strong>
        <span>Runtime Console</span>
      </div>
    </div>
    <div
      class="title-bar__controls pointer-events-auto"
      data-tauri-drag-region="false"
      @mousedown.stop
    >
      <ThemeToggle />
      <WindowControls />
    </div>
  </header>
</template>

<script setup lang="ts">
import { appWindow } from '@tauri-apps/api/window'
import ThemeToggle from './ThemeToggle.vue'
import WindowControls from './WindowControls.vue'

const startDragging = async (event: MouseEvent) => {
  if (event.button === 0) {
    try {
      await appWindow.startDragging()
    } catch (error) {
      console.error('Failed to start dragging:', error)
    }
  }
}
</script>

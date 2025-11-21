<template>
  <div ref="root" class="mirror-select__control">
    <span class="mirror-select__icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <circle cx="12" cy="12" r="6.75" opacity="0.4" />
        <path
          d="M4.75 12h14.5M12 4.75c2.5 2.15 2.5 10.35 0 14.5M12 4.75c-2.5 2.15-2.5 10.35 0 14.5"
          stroke-linecap="round"
        />
      </svg>
    </span>

    <button
      ref="trigger"
      type="button"
      class="mirror-select__input"
      :class="{ 'mirror-select__input--disabled': disabled }"
      :data-open="isOpen ? 'true' : null"
      :aria-expanded="isOpen ? 'true' : 'false'"
      aria-haspopup="listbox"
      :aria-controls="menuId"
      :aria-labelledby="computedLabelId + ' ' + valueId"
      :aria-disabled="disabled ? 'true' : 'false'"
      @click="handleTriggerClick"
      @keydown="handleTriggerKeydown"
    >
      <span :id="valueId" class="mirror-select__value" :class="{ 'mirror-select__value--empty': !selectedOption }">
        <template v-if="selectedOption">
          <span class="mirror-select__value-label">{{ selectedOption.label }}</span>
          <span class="mirror-select__value-url">{{ selectedOption.value }}</span>
        </template>
        <template v-else>
          <span class="mirror-select__placeholder">暂无可用镜像</span>
        </template>
      </span>
    </button>

    <span class="mirror-select__chevron" aria-hidden="true">
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M6 8l4 4 4-4" stroke-linecap="round" stroke-linejoin="round" />
      </svg>
    </span>
    <span class="mirror-select__shine" aria-hidden="true" />
    <span class="mirror-select__border" aria-hidden="true" />

    <transition name="mirror-select__dropdown-transition">
      <ul
        v-if="isOpen"
        :id="menuId"
        class="mirror-select__dropdown"
        role="listbox"
        :aria-activedescendant="activeDescendantId"
        :aria-labelledby="computedLabelId"
        tabindex="-1"
      >
        <template v-if="options.length">
          <li
            v-for="(option, index) in options"
            :id="getOptionId(index)"
            :key="option.value"
            :ref="(el) => setOptionRef(el, index)"
            role="option"
            class="mirror-select__option"
            :class="{
              'mirror-select__option--active': index === highlightedIndex,
              'mirror-select__option--selected': option.value === modelValue,
            }"
            :aria-selected="option.value === modelValue"
            @mouseenter="highlight(index)"
            @mousedown.prevent
            @click="selectOption(option)"
          >
            <span class="mirror-select__option-label">{{ option.label }}</span>
            <span class="mirror-select__option-url">{{ option.value }}</span>
          </li>
        </template>
        <li v-else class="mirror-select__empty">暂无可用镜像源</li>
      </ul>
    </transition>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onBeforeUpdate, onMounted, ref, watch } from 'vue'

type MirrorOption = {
  label: string
  value: string
}

const props = defineProps<{
  modelValue: string
  options: MirrorOption[]
  disabled?: boolean
  labelId?: string
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void
}>()

const instanceId = `mirror-select-${Math.random().toString(36).slice(2, 10)}`
const menuId = `${instanceId}-menu`
const valueId = `${instanceId}-value`

const computedLabelId = computed(() => props.labelId ?? `${instanceId}-label`)

const isOpen = ref(false)
const highlightedIndex = ref(-1)
const trigger = ref<HTMLElement | null>(null)
const root = ref<HTMLElement | null>(null)
const optionRefs = ref<HTMLElement[]>([])

const options = computed(() => props.options ?? [])

const selectedOption = computed(() => options.value.find((option) => option.value === props.modelValue) ?? null)

const activeDescendantId = computed(() =>
  highlightedIndex.value >= 0 ? getOptionId(highlightedIndex.value) : undefined,
)

function getOptionId(index: number) {
  return `${instanceId}-option-${index}`
}

function setOptionRef(el: Element | null, index: number) {
  if (!el) {
    return
  }
  optionRefs.value[index] = el as HTMLElement
}

function selectedIndex() {
  return options.value.findIndex((option) => option.value === props.modelValue)
}

function openDropdown() {
  if (props.disabled || !options.value.length) {
    return
  }
  isOpen.value = true
  nextTick(() => {
    const index = selectedIndex()
    if (index >= 0) {
      highlight(index)
    } else if (options.value.length) {
      highlight(0)
    }
  })
}

function closeDropdown(focusTrigger = false) {
  if (!isOpen.value) {
    return
  }
  isOpen.value = false
  highlightedIndex.value = -1
  if (focusTrigger) {
    nextTick(() => trigger.value?.focus())
  }
}

function handleTriggerClick() {
  if (props.disabled) {
    return
  }
  if (isOpen.value) {
    closeDropdown(true)
  } else {
    openDropdown()
  }
}

function handleTriggerKeydown(event: KeyboardEvent) {
  if (props.disabled) {
    return
  }

  switch (event.key) {
    case 'ArrowDown':
    case 'Down':
      event.preventDefault()
      if (!isOpen.value) {
        openDropdown()
      }
      moveHighlight(1)
      break
    case 'ArrowUp':
    case 'Up':
      event.preventDefault()
      if (!isOpen.value) {
        openDropdown()
      }
      moveHighlight(-1)
      break
    case 'Home':
      event.preventDefault()
      if (!isOpen.value) {
        openDropdown()
      }
      highlight(0)
      break
    case 'End':
      event.preventDefault()
      if (!isOpen.value) {
        openDropdown()
      }
      highlight(options.value.length - 1)
      break
    case 'Enter':
    case ' ':
    case 'Spacebar':
      event.preventDefault()
      if (!isOpen.value) {
        openDropdown()
      } else if (highlightedIndex.value >= 0) {
        const option = options.value[highlightedIndex.value]
        if (option) {
          selectOption(option)
        }
      }
      break
    case 'Escape':
      event.preventDefault()
      closeDropdown(true)
      break
    case 'Tab':
      closeDropdown()
      break
  }
}

function moveHighlight(step: number) {
  if (!options.value.length) {
    highlightedIndex.value = -1
    return
  }

  let nextIndex = highlightedIndex.value
  if (nextIndex === -1) {
    const selected = selectedIndex()
    nextIndex = selected >= 0 ? selected : step > 0 ? 0 : options.value.length - 1
  } else {
    nextIndex = nextIndex + step
  }

  if (nextIndex < 0) {
    nextIndex = options.value.length - 1
  } else if (nextIndex >= options.value.length) {
    nextIndex = 0
  }

  highlight(nextIndex)
}

function highlight(index: number) {
  if (!options.value.length) {
    highlightedIndex.value = -1
    return
  }
  const clampedIndex = Math.min(Math.max(index, 0), options.value.length - 1)
  highlightedIndex.value = clampedIndex
  nextTick(() => {
    const el = optionRefs.value[clampedIndex]
    el?.scrollIntoView({ block: 'nearest' })
  })
}

function selectOption(option: MirrorOption) {
  emit('update:modelValue', option.value)
  closeDropdown(true)
}

function handleClickOutside(event: MouseEvent) {
  if (!root.value) {
    return
  }

  const target = event.target as Node | null
  if (target && root.value.contains(target)) {
    return
  }
  closeDropdown()
}

watch(
  () => props.modelValue,
  () => {
    if (!isOpen.value) {
      return
    }
    const index = selectedIndex()
    if (index >= 0) {
      highlight(index)
    }
  },
)

watch(
  () => props.disabled,
  (disabled) => {
    if (disabled) {
      closeDropdown()
    }
  },
)

onMounted(() => {
  document.addEventListener('mousedown', handleClickOutside)
})

onBeforeUnmount(() => {
  document.removeEventListener('mousedown', handleClickOutside)
})

onBeforeUpdate(() => {
  optionRefs.value = []
})
</script>

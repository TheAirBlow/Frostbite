<template>
  <details class="group/ph text-xs">
    <summary class="text-base-content/60 hover:text-base-content inline-flex cursor-pointer list-none items-center gap-1.5 rounded-md py-0.5 font-medium transition-colors duration-150 select-none [&::-webkit-details-marker]:hidden">
      <Icon name="fa6-solid:chevron-down" size="9" class="-rotate-90 transition-transform duration-150 group-open/ph:rotate-0! motion-reduce:transition-none rtl:rotate-90" />
      <Icon name="fa6-solid:code" size="11" />
      {{ t(title) }}
    </summary>

    <div class="bg-base-100 border-base-300 mt-2 flex flex-col gap-3 rounded-[0.75rem] border p-2">
      <section v-for="g in groups" :key="g.label">
        <h5 class="text-base-content/50 px-2 pb-1 text-[0.65rem] font-semibold tracking-wider uppercase">{{ t(g.label) }}</h5>
        <ul>
          <li v-for="name in g.names" :key="name">
            <button
              type="button"
              class="hover:bg-base-content/5 focus-visible:bg-base-content/5 group/row grid w-full grid-cols-[9.5rem_1fr_auto] items-baseline gap-x-3 gap-y-0.5 rounded-md px-2 py-1 max-sm:py-1.5 text-start transition-colors duration-150 focus-visible:outline-none max-sm:grid-cols-[1fr_auto]"
              :title="insert ? t('Insert') : t('Copy')"
              @click="pick(name)"
            >
              <code class="bg-base-content/8 text-base-content/90 justify-self-start rounded px-1.5 py-px font-mono">{{ braced(name) }}</code>
              <span class="text-base-content/60 max-sm:col-span-2 max-sm:row-start-2">{{ t(placeholderHints[name]) }}</span>
              <Icon
                :name="copied === name ? 'fa6-solid:check' : insert ? 'fa6-solid:plus' : 'fa6-regular:copy'"
                size="10"
                class="self-center opacity-0 transition-opacity duration-150 group-hover/row:opacity-60 group-focus-visible/row:opacity-60 max-sm:col-start-2 max-sm:row-start-1"
                :class="{ 'text-success opacity-100!': copied === name }"
              />
            </button>
          </li>
        </ul>
      </section>

      <p class="border-base-300 text-base-content/50 flex items-start gap-2 border-t px-2 pt-2">
        <Icon name="fa6-solid:circle-info" size="11" class="mt-0.5 shrink-0" />
        {{ t('Add :upper or :lower to change the case, like {protocol:upper}. Unknown placeholders are left as written.') }}
      </p>
    </div>
  </details>
</template>

<script setup lang="ts">
// `insert` adds a clicked placeholder to the field the reference belongs to; without it a click copies it.
const props = withDefaults(defineProps<{ names: string[], title?: string, insert?: (token: string) => void }>(), { title: 'Placeholders', insert: undefined })
const { t } = useT()
const { copy } = useClipboard()
const copied = ref('')

const braced = (name: string) => `{${name}}`

const groups = computed(() => placeholderGroups
  .map(g => ({ label: g.label, names: g.names.filter(n => props.names.includes(n)) }))
  .filter(g => g.names.length))

let timer: ReturnType<typeof setTimeout> | undefined
async function pick(name: string) {
  if (props.insert) props.insert(braced(name))
  else await copy(braced(name))
  copied.value = name
  clearTimeout(timer)
  timer = setTimeout(() => (copied.value = ''), 1200)
}
onBeforeUnmount(() => clearTimeout(timer))
</script>

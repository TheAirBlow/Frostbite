<template>
  <div ref="root" class="relative">
    <svg class="pointer-events-none absolute inset-0 z-10 size-full overflow-visible">
      <defs>
        <marker v-for="m in markers" :id="`arrow-${m.id}`" :key="m.id" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0 0L10 5L0 10z" :fill="m.color" />
        </marker>
      </defs>
      <g v-for="(p, i) in paths" :key="i">
        <path :d="p.d" fill="none" :stroke="p.color" stroke-width="2" :stroke-dasharray="p.dash" :marker-end="`url(#arrow-${p.kind})`" opacity="0.9" />
        <g :transform="`translate(${p.mx}, ${p.my})`">
          <rect x="-4" :y="-10" :width="p.label.length * 6.2 + 12" height="20" rx="10" fill="var(--color-base-100)" stroke="var(--color-base-300)" />
          <text x="2" y="4" font-size="11" fill="var(--color-base-content)" opacity="0.75">{{ p.label }}</text>
        </g>
      </g>
    </svg>

    <div class="grid gap-x-16 gap-y-10 sm:grid-cols-2 xl:grid-cols-3">
      <div v-for="n in topology.nodes" :key="n.id" :data-node="n.id" class="surface relative z-0 p-3">
        <div class="mb-2 flex items-center gap-2">
          <span class="text-xl">{{ flag(n.country) }}</span>
          <div class="min-w-0"><p class="font-medium">{{ n.name }}</p><p class="text-base-content/50 truncate font-mono text-[11px]">{{ n.address }}</p></div>
        </div>
        <div v-for="d in n.daemons" :key="d.id" class="mb-1.5 last:mb-0">
          <p class="text-base-content/50 mb-1 flex items-center gap-1.5 text-[11px] tracking-wide uppercase"><Dot :tone="d.online ? 'success' : 'muted'" /> {{ d.name }} · {{ coreLabels[d.kind] ?? d.kind }}</p>
          <div v-for="i in d.inbounds" :key="i.id" :data-inbound="i.id" class="bg-base-100 border-base-300 mb-1 flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs">
            <Icon :name="i.relay ? 'fa6-solid:right-left' : 'fa6-solid:plug'" size="11" :class="i.relay ? 'text-secondary' : 'text-base-content/50'" />
            <span class="min-w-0 flex-1 truncate">{{ i.tag }}</span>
            <span class="text-base-content/50 font-mono">:{{ i.port }}</span>
          </div>
          <p v-if="!d.inbounds.length" class="text-base-content/40 text-xs">{{ $t('no inbounds') }}</p>
        </div>
        <p v-if="!n.daemons.length" class="text-base-content/40 text-xs">{{ $t('no daemons') }}</p>
      </div>

      <div v-if="customs.length" data-custom class="surface relative z-0 border-dashed p-3">
        <p class="mb-2 flex items-center gap-2 font-medium"><Icon name="fa6-solid:cloud" size="14" class="text-accent" /> {{ $t('Outside') }}</p>
        <div v-for="c in customs" :key="c" :data-custom-target="c" class="bg-base-100 border-base-300 mb-1 rounded-lg border px-2.5 py-1.5 font-mono text-xs">{{ c }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { Topology } from '~/types/api'

const props = defineProps<{ topology: Topology }>()
const root = useTemplateRef('root')
const paths = ref<{ d: string, color: string, dash: string, kind: string, label: string, mx: number, my: number }[]>([])

const colors: Record<string, string> = { relay: 'var(--color-secondary)', chain: 'var(--color-primary)', custom: 'var(--color-accent)' }
const dashes: Record<string, string> = { relay: '6 5', chain: '', custom: '2 5' }
const markers = Object.entries(colors).map(([id, color]) => ({ id, color }))
const customs = computed(() => [...new Set(props.topology.edges.filter(e => e.kind === 'custom' && e.custom).map(e => e.custom!))])

function rectOf(el: Element, base: DOMRect) {
  const r = el.getBoundingClientRect()
  return { l: r.left - base.left, r: r.right - base.left, t: r.top - base.top, b: r.bottom - base.top, cx: r.left - base.left + r.width / 2, cy: r.top - base.top + r.height / 2 }
}

function layout() {
  const el = root.value
  if (!el) return
  const base = el.getBoundingClientRect()
  const out: typeof paths.value = []

  for (const e of props.topology.edges) {
    const from = (e.from_inbound && el.querySelector(`[data-inbound="${e.from_inbound}"]`)) || el.querySelector(`[data-node="${e.from_node}"]`)
    const to = e.kind === 'custom'
      ? el.querySelector(`[data-custom-target="${e.custom}"]`)
      : (e.to_inbound && el.querySelector(`[data-inbound="${e.to_inbound}"]`)) || el.querySelector(`[data-node="${e.to_node}"]`)
    if (!from || !to) continue

    const a = rectOf(from, base)
    const b = rectOf(to, base)
    const goingRight = a.cx < b.cx - 20
    const goingLeft = a.cx > b.cx + 20
    let x1 = a.r, x2 = b.l, c1 = 70, c2 = -70

    if (goingLeft) {
      x1 = a.l
      x2 = b.r
      c1 = -70
      c2 = 70
    }
    else if (!goingRight) {
      // same column: loop out to the right so the line stays visible
      x1 = a.r
      x2 = b.r
      c1 = 60
      c2 = 60
    }
    const y1 = a.cy
    const y2 = b.cy
    out.push({
      d: `M${x1},${y1} C${x1 + c1},${y1} ${x2 + c2},${y2} ${x2},${y2}`,
      color: colors[e.kind]!, dash: dashes[e.kind]!, kind: e.kind, label: e.label,
      mx: (x1 + x2) / 2 + (goingRight || goingLeft ? 0 : 36), my: (y1 + y2) / 2,
    })
  }
  paths.value = out
}

watch(() => props.topology, () => nextTick(layout), { deep: true, immediate: true })
onMounted(() => nextTick(layout))
useResizeObserver(root, () => layout())
</script>

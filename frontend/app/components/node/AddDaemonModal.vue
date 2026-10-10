<template>
  <AppModal :title="enrollment ? 'Connect the daemon' : 'Add a daemon'" :subtitle="`on ${node.name}`" max-width="max-w-xl" @close="close">
    <EnrollPanel v-if="enrollment" :enrollment="enrollment" :kind="kind" />
    <form v-else id="add-daemon" class="flex flex-col gap-4" novalidate @submit.prevent="submit()">
      <FormField label="Core" name="kind" class="gap-2">
      <div class="grid gap-2 sm:grid-cols-2">
        <button v-for="c in cores" :key="c.kind" type="button" class="surface hover:border-primary/60 flex flex-col gap-1 p-3 text-left transition" :class="{ 'border-primary ring-primary/40 ring-1': kind === c.kind }" @click="pick(c.kind)">
          <span class="flex items-center justify-between font-display text-lg font-semibold">{{ c.display_name }} <Icon v-if="kind === c.kind" name="fa6-solid:circle-check" size="14" class="text-primary" /></span>
          <span class="text-base-content/60 text-xs">{{ $t(blurb[c.kind]) }}</span>
          <span v-if="c.caps.protocols?.length" class="mt-1 flex flex-wrap gap-1"><span v-for="p in c.caps.protocols.slice(0, 6)" :key="p" class="badge badge-xs badge-ghost">{{ protocolLabels[p] ?? p }}</span></span>
        </button>
      </div>
      </FormField>
      <FormField label="Name" name="name" hint="Just a label for this daemon.">
        <input v-model="name" class="input w-full" :placeholder="kind" autocomplete="off">
      </FormField>
      <p v-if="existing" class="text-warning text-sm">This node already has a {{ coreLabels[kind] }} daemon. That works, but two of the same core will compete for ports.</p>
    </form>
    <template v-if="!enrollment" #footer>
      <FormBanner class="mb-2" />
      <div class="flex justify-end"><button form="add-daemon" class="btn btn-primary" :disabled="saving">{{ $t('Create daemon') }}</button></div>
    </template>
  </AppModal>
</template>

<script setup lang="ts">
import type { CoreInfo, Enrollment, PanelNode } from '~/types/api'

const props = defineProps<{ node: PanelNode }>()
const emit = defineEmits<{ close: [], created: [] }>()

const { data: cores } = useAsyncData('cores', () => useApi<CoreInfo[]>('/cores'))
const kind = ref('xray')
const name = ref('')
const enrollment = ref<Enrollment | null>(null)

const blurb: Record<string, string> = {
  xray: 'The reference VLESS/REALITY core. Adds and removes users without dropping connections.',
  singbox: 'Widest protocol range: Hysteria2, TUIC, AnyTLS, Naive, WireGuard and more. Users change live.',
  mtproto: 'A Telegram-only proxy. Each user gets their own secret, so usage and limits work per person. Pretends to be a visit to a real site.',
  turnable: 'Hides a tunnel in a public VK call and leads it to one destination on this node, like a WireGuard inbound. Users change live.',
  edge: 'Shares port 443 between the other daemons on this node by reading the TLS server name. Optional decoy for everything else.',
}

const formApi = useForm(() => ({ kind: kind.value, name: name.value }), v => problems({
  kind: checkRequired(v.kind, 'Pick a core'),
  name: v.name && !/^[\w .-]{1,40}$/.test(v.name) ? 'Use up to 40 letters, digits, spaces, dots, dashes or underscores' : undefined,
}))
const existing = computed(() => props.node.daemons.some(d => d.kind === kind.value))
function pick(k: string) {
  kind.value = k
}

const { loading: saving, run: submit } = useAsyncAction(async () => {
  const res = await useApi<{ enrollment: Enrollment }>(`/nodes/${props.node.id}/daemons`, { method: 'POST', body: { kind: kind.value, name: name.value || kind.value } })
  enrollment.value = res.enrollment
  emit('created')
}, undefined, formApi)

function close() {
  emit('close')
}
</script>

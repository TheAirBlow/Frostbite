<template>
  <div class="flex flex-col gap-3">
    <p class="text-base-content/60 text-sm">
      {{ $t('A host is one way clients reach this inbound. Add one per entry point: the server itself, a CDN domain, a relay. Every host becomes its own profile in subscriptions.') }}
    </p>
    <p class="text-base-content/50 text-xs">
      {{ $t('Remark placeholders:') }} <span class="font-mono">{node} {country} {inbound} {protocol} {transport} {security} {user}</span>
    </p>

    <div v-for="h in hosts" :key="h.id" class="surface p-3">
      <div class="flex items-center gap-2">
        <Icon :name="h.bridge_inbound_id ? 'fa6-solid:bridge' : 'fa6-solid:globe'" size="14" class="text-base-content/60" />
        <p class="min-w-0 flex-1 truncate font-medium">{{ h.remark }}</p>
        <span v-if="h.bridge_inbound_id" class="badge badge-sm badge-secondary badge-soft">{{ $t('relay') }}</span>
        <span v-if="!h.enabled" class="badge badge-sm badge-neutral">{{ $t('off') }}</span>
        <button class="btn btn-ghost btn-xs" @click="editing = editing === h.id ? 0 : h.id">{{ editing === h.id ? 'Close' : 'Edit' }}</button>
      </div>
      <p class="text-base-content/50 mt-1 font-mono text-xs">{{ h.address || nodeAddress }}:{{ h.port || inbound.port }}<template v-if="h.sni"> · sni {{ h.sni }}</template><template v-if="h.path"> · {{ h.path }}</template></p>

      <form v-if="editing === h.id" class="mt-3 flex flex-col gap-3" @submit.prevent="save(h)">
        <FormField label="Remark"><input v-model="draft.remark" class="input w-full"></FormField>
        <div class="grid gap-3 sm:grid-cols-3">
          <FormField class="sm:col-span-2" label="Address" :hint="h.bridge_inbound_id ? 'Kept in sync with the relay.' : 'Empty uses the node address.'"><input v-model="draft.address" class="input w-full font-mono" :placeholder="nodeAddress" :readonly="!!h.bridge_inbound_id"></FormField>
          <FormField label="Port" hint="Empty uses the inbound port."><input v-model.number="draft.port" type="number" class="input w-full" :placeholder="String(inbound.port)" :readonly="!!h.bridge_inbound_id"></FormField>
        </div>
        <div class="grid gap-3 sm:grid-cols-2">
          <FormField label="SNI override"><input v-model="draft.sni" class="input w-full font-mono"></FormField>
          <FormField label="Host header override"><input v-model="draft.host" class="input w-full font-mono"></FormField>
          <FormField label="Path override"><input v-model="draft.path" class="input w-full font-mono"></FormField>
          <FormField label="Fingerprint">
            <select v-model="draft.fingerprint" class="select w-full"><option value="">{{ $t('Inbound default') }}</option><option v-for="f in ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random']" :key="f">{{ f }}</option></select>
          </FormField>
        </div>
        <FormField label="ALPN"><ChipInput v-model="draft.alpn" :placeholder="$t('h2, http/1.1')" /></FormField>
        <ToggleRow v-model="draft.insecure" label="Allow insecure certificates" hint="Tells clients not to verify the certificate. Useful with self signed ones. Xray ignores it." />
        <ToggleRow v-model="draft.enabled" label="Enabled" />
        <Advanced>
          <ToggleRow :model-value="!!draft.mux?.enabled" label="Multiplexing" @update:model-value="draft.mux = { ...(draft.mux ?? {}), enabled: $event } as Mux" />
          <ToggleRow :model-value="!!draft.fragment?.enabled" label="Fragment the TLS hello" hint="Helps against some DPI. Only clients that support it use it." @update:model-value="draft.fragment = { ...(draft.fragment ?? {}), enabled: $event } as Fragment" />
          <div v-if="draft.fragment?.enabled" class="grid gap-3 sm:grid-cols-3">
            <FormField label="Packets"><input v-model="draft.fragment.packets" class="input w-full" :placeholder="$t('tlshello')"></FormField>
            <FormField label="Length"><input v-model="draft.fragment.length" class="input w-full" placeholder="100-200"></FormField>
            <FormField label="Interval (ms)"><input v-model="draft.fragment.interval" class="input w-full" placeholder="10-20"></FormField>
          </div>
        </Advanced>
        <div class="flex justify-between">
          <ConfirmButton type="button" class="btn btn-ghost btn-sm text-error" confirm-label="Delete?" @confirmed="remove(h.id)"><Icon name="fa6-solid:trash" size="12" /> {{ $t('Delete') }}</ConfirmButton>
          <button class="btn btn-primary btn-sm">{{ $t('Save host') }}</button>
        </div>
      </form>
    </div>

    <button class="btn btn-sm btn-outline self-start" @click="add"><Icon name="fa6-solid:plus" size="12" /> {{ $t('Add host') }}</button>
  </div>
</template>

<script setup lang="ts">
import type { Fragment, Host, Inbound, Mux } from '~/types/api'

const props = defineProps<{ inboundId: number, inbound: Inbound, nodeAddress: string }>()
const emit = defineEmits<{ changed: [] }>()
const toast = useToast()

const hosts = computed(() => props.inbound.hosts)
const editing = ref(0)
const draft = ref<Host>({} as Host)

watch(editing, (id) => {
  const h = hosts.value.find(x => x.id === id)
  if (h) draft.value = structuredClone(toRaw(h))
})

function body(h: Host) {
  return {
    inbound_id: props.inboundId, remark: h.remark, address: h.address, port: h.port || null, sni: h.sni, host: h.host, path: h.path,
    alpn: h.alpn, fingerprint: h.fingerprint, insecure: h.insecure, mux: h.mux, fragment: h.fragment, enabled: h.enabled, sort: h.sort,
  }
}

async function add() {
  try {
    const h = await useApi<Host>('/hosts', { method: 'POST', body: { inbound_id: props.inboundId, remark: '{node} {protocol}', alpn: [], enabled: true } })
    emit('changed')
    await nextTick()
    editing.value = h.id
  }
  catch (e) {
    toast.error(errorMessage(e))
  }
}

async function save(h: Host) {
  try {
    await useApi(`/hosts/${h.id}`, { method: 'PUT', body: body(draft.value) })
    toast.success('Saved.')
    editing.value = 0
    emit('changed')
  }
  catch (e) {
    toast.error(errorMessage(e))
  }
}

async function remove(id: number) {
  try {
    await useApi(`/hosts/${id}`, { method: 'DELETE' })
    editing.value = 0
    emit('changed')
  }
  catch (e) {
    toast.error(errorMessage(e))
  }
}
</script>

<template>
  <Skeleton v-if="!daemon" :rows="4" />
  <form v-else class="flex flex-col gap-4" novalidate @submit.prevent="save()">
    <FormField label="Name" name="name" required><input v-model="form.name" class="input w-full"></FormField>
    <ToggleRow v-model="form.enabled" label="Enabled" hint="Turning it off disconnects the daemon and stops serving its inbounds." />

    <template v-if="daemon.kind === 'edge'">
      <FormField label="Listen on" name="edge_listen" required hint="Addresses the edge accepts connections on. Inbounds placed behind it share these ports."><ChipInput v-model="form.edge_listen" placeholder=":443" :check="checkListenAddr" /></FormField>
      <FormField label="Everything else goes to" name="edge_default" hint="Probes, browsers and unknown names are passed to this host:port, such as a real website or a decoy on this machine. Empty drops them."><input v-model="form.edge_default" class="input w-full font-mono" placeholder="127.0.0.1:8080"></FormField>
    </template>

    <div v-else class="grid gap-3 sm:grid-cols-2">
      <FormField label="Log level" name="log_level">
        <select v-model="form.log_level" class="select w-full"><option v-for="l in ['debug', 'info', 'warning', 'error', 'none']" :key="l" :value="l">{{ l }}</option></select>
      </FormField>
      <FormField label="Default outbound" name="final_outbound" hint="Where traffic goes when no routing rule matches.">
        <select v-model="form.final_outbound" class="select w-full">
          <option value="direct">{{ $t('direct') }}</option>
          <option v-for="o in outbounds" :key="o.id" :value="o.tag">{{ o.tag }}</option>
        </select>
      </FormField>
    </div>

    <template v-if="daemon.kind !== 'edge'">
      <FormField label="DNS servers" name="dns_servers" hint="Plain IPs, https:// or tls:// URLs. The core resolves domains with these."><ChipInput v-model="form.dns_servers" placeholder="1.1.1.1" :check="checkDnsServer" /></FormField>
      <FormField label="DNS strategy" name="dns_strategy">
        <select v-model="form.dns_strategy" class="select w-full"><option v-for="s in ['prefer_ipv4', 'prefer_ipv6', 'ipv4_only', 'ipv6_only']" :key="s" :value="s">{{ s }}</option></select>
      </FormField>
    </template>

    <Advanced v-if="daemon.kind !== 'edge'" :title="$t('Raw config patch')">
      <p class="text-base-content/60 mb-2 text-xs">A JSON object merged over the generated {{ coreLabels[daemon.kind] }} config. <span class="font-mono">{{ $t('null') }}</span> {{ $t('removes a key. Use it for anything the forms do not cover.') }}</p>
      <FormField label="Patch" name="raw_patch"><JsonField v-model="form.raw_patch" :rows="8" placeholder='{ "policy": { } }' /></FormField>
    </Advanced>

    <Section :title="$t('About this daemon')">
      <dl class="grid grid-cols-2 gap-x-4 gap-y-1.5 text-sm">
        <dt class="text-base-content/50">{{ $t('Core') }}</dt><dd>{{ daemon.core_version || '—' }}</dd>
        <dt class="text-base-content/50">{{ $t('Agent') }}</dt><dd>{{ daemon.agent_version || '—' }}</dd>
        <dt class="text-base-content/50">{{ $t('Host') }}</dt><dd>{{ daemon.host_info.hostname || '—' }} <span class="text-base-content/50">{{ daemon.host_info.os }}/{{ daemon.host_info.arch }}</span></dd>
        <dt class="text-base-content/50">{{ $t('Revision') }}</dt><dd>{{ daemon.applied_rev }} applied · {{ daemon.desired_rev }} wanted</dd>
        <dt class="text-base-content/50">{{ $t('Last seen') }}</dt><dd>{{ daemon.live.online ? 'now' : formatRelative(daemon.last_seen) }}</dd>
        <dt class="text-base-content/50">{{ $t('User changes') }}</dt><dd>{{ hot ? $t('Applied live') : $t('Needs a restart') }}</dd>
      </dl>
    </Section>

    <FormFooter>
      <span />
      <button class="btn btn-primary" :disabled="saving"><span v-if="saving" class="loading loading-spinner loading-xs" /> {{ $t('Save changes') }}</button>
    </FormFooter>
  </form>
</template>

<script setup lang="ts">
import type { CoreInfo, Daemon, Outbound, PanelNode } from '~/types/api'

const props = defineProps<{ id: number }>()
const emit = defineEmits<{ title: [m: { title: string, subtitle?: string }], done: [] }>()

const daemon = ref<Daemon | null>(null)
const outbounds = ref<Outbound[]>([])
const cores = ref<CoreInfo[]>([])
const form = reactive({ name: '', enabled: true, log_level: 'warning', dns_servers: [] as string[], dns_strategy: 'prefer_ipv4', final_outbound: 'direct', raw_patch: null as Record<string, unknown> | null, edge_listen: [] as string[], edge_default: '' })

const checkListenAddr = (v: string) => (/^(\[[^\]]+\]|[^:\s]*):\d{1,5}$/.test(v) && !checkPort(v.slice(v.lastIndexOf(':') + 1)) ? undefined : 'Use an address like :443 or 0.0.0.0:443')
const checkDnsServer = (v: string) => (/^(https|tls|quic|h3):\/\//.test(v) ? checkUrl(v, ['https:', 'tls:', 'quic:', 'h3:']) : checkIp(v) && 'Use a plain IP, or an https:// or tls:// address')

const formApi = useForm(() => (daemon.value ? form : null), f => problems({
  name: checkRequired(f.name, 'Give the daemon a name'),
  edge_listen: daemon.value?.kind === 'edge' ? checkRequired(f.edge_listen, 'Add at least one address to listen on') : undefined,
  edge_default: f.edge_default ? checkHostPort(f.edge_default) : undefined,
}))

const hot = computed(() => cores.value.find(c => c.kind === daemon.value?.kind)?.caps.hot_users)

onMounted(async () => {
  const [nodes, outs, cs] = await Promise.all([useApi<PanelNode[]>('/nodes'), useApi<Outbound[]>('/outbounds'), useApi<CoreInfo[]>('/cores')])
  const d = nodes.flatMap(n => n.daemons).find(x => x.id === props.id)
  if (!d) return
  daemon.value = d
  outbounds.value = outs.filter(o => o.daemon_id === d.id)
  cores.value = cs
  Object.assign(form, { name: d.name, enabled: d.enabled, log_level: d.log_level, dns_servers: [...d.dns_servers], dns_strategy: d.dns_strategy, final_outbound: d.final_outbound, raw_patch: d.raw_patch, edge_listen: [...(d.edge_listen ?? [])], edge_default: d.edge_default ?? '' })
  emit('title', { title: d.name, subtitle: `${coreLabels[d.kind] ?? d.kind} daemon on ${nodes.find(n => n.id === d.node_id)?.name}` })
})

const { loading: saving, run: save } = useAsyncAction(async () => {
  await useApi(`/daemons/${props.id}`, { method: 'PUT', body: { ...form, raw_patch: form.raw_patch ?? null } })
  await refreshNuxtData()
  emit('done')
}, 'Saved.', formApi)
</script>

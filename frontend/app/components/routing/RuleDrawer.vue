<template>
  <Skeleton v-if="!ready" :rows="4" />
  <form v-else class="flex flex-col gap-4" novalidate @submit.prevent="save()">
    <div v-if="!id && templates.length" class="flex flex-col gap-1">
      <p class="fieldset-legend">{{ $t('Start from a recipe') }}</p>
      <div class="flex flex-wrap gap-1.5">
        <button v-for="t in templates" :key="t.id" type="button" class="btn btn-xs rounded-full btn-ghost bg-base-200" :title="t.description" @click="useTemplate(t)">{{ t.label }}</button>
      </div>
    </div>

    <FormField label="Name" name="name" hint="Optional. A short reminder of what this rule is for."><input v-model="form.name" class="input w-full" :placeholder="$t('Netflix through Frankfurt')"></FormField>

    <div class="grid gap-3 sm:grid-cols-2">
      <FormField label="Applies to" name="daemon_id">
        <select v-model="form.daemon_id" class="select w-full">
          <option :value="null">{{ $t('Every daemon that has the outbound') }}</option>
          <optgroup v-for="n in nodes" :key="n.id" :label="`${flag(n.country)} ${n.name}`"><option v-for="d in n.daemons" :key="d.id" :value="d.id">{{ d.name }}</option></optgroup>
        </select>
      </FormField>
      <FormField label="Send it to" name="outbound" required>
        <select v-model="form.outbound" class="select w-full">
          <option value="direct">{{ $t('direct') }}</option>
          <option value="block">{{ $t('block') }}</option>
          <option v-for="o in outboundChoices" :key="o" :value="o">{{ o }}</option>
        </select>
      </FormField>
    </div>

    <div class="divider my-0">{{ $t('When traffic matches all of') }}</div>
    <FieldError name="match" />
    <FormField label="Domains" name="match.domain_suffix" hint="The domain and all its subdomains."><ChipInput v-model="match.domain_suffix" :placeholder="$t('netflix.com')" :check="checkDomainLike" /></FormField>
    <FormField label="Geosite lists" name="match.geosite" hint="Ready made lists like netflix, google, category-ads-all, cn."><ChipInput v-model="match.geosite" :placeholder="$t('netflix')" /></FormField>
    <FormField label="Countries (GeoIP)" name="match.geoip" hint="Two letter codes of where the destination IP is."><ChipInput v-model="match.geoip" :placeholder="$t('ru')" :check="checkCountry" /></FormField>
    <FormField label="Ports" name="match.port"><ChipInput v-model="match.port" :placeholder="$t('443 or 6881-6889')" :check="checkPortRange" /></FormField>
    <FormField label="Detected protocol" name="match.protocol" hint="Needs sniffing on the inbound.">
      <div class="flex flex-wrap gap-1.5"><button v-for="p in ['bittorrent', 'quic', 'http', 'tls', 'dns', 'stun']" :key="p" type="button" class="btn btn-xs rounded-full" :class="(match.protocol ?? []).includes(p) ? 'btn-primary' : 'btn-ghost bg-base-200'" @click="toggleProto(p)">{{ p }}</button></div>
    </FormField>

    <Advanced :title="$t('More conditions')">
      <div class="flex flex-col gap-3">
        <FormField label="Exact domains" name="match.domain"><ChipInput v-model="match.domain" :placeholder="$t('www.example.com')" /></FormField>
        <FormField label="Domain keywords" name="match.domain_keyword"><ChipInput v-model="match.domain_keyword" :placeholder="$t('tracker')" /></FormField>
        <FormField label="IP ranges" name="match.ip_cidr"><ChipInput v-model="match.ip_cidr" placeholder="10.0.0.0/8" :check="checkCidr" /></FormField>
        <FormField label="Network" name="match.network"><select v-model="match.network" class="select w-full"><option :value="undefined">{{ $t('Any') }}</option><option value="tcp">{{ $t('tcp') }}</option><option value="udp">{{ $t('udp') }}</option></select></FormField>
        <FormField label="Only these inbound tags" name="match.inbound_tags"><ChipInput v-model="match.inbound_tags" :placeholder="$t('vless-reality-443')" /></FormField>
        <FormField label="Only these users" name="match.users" hint="Internal names like u12. Users show up as u + their id."><ChipInput v-model="match.users" placeholder="u12" /></FormField>
      </div>
    </Advanced>

    <ToggleRow v-model="form.enabled" label="Enabled" />

    <FormFooter>
      <ConfirmButton v-if="id" type="button" class="btn btn-ghost text-error" confirm-label="Delete?" @confirmed="remove"><Icon name="fa6-solid:trash" size="13" /> {{ $t('Delete') }}</ConfirmButton>
      <span v-else />
      <button class="btn btn-primary" :disabled="saving"><span v-if="saving" class="loading loading-spinner loading-xs" /> {{ id ? 'Save changes' : 'Add rule' }}</button>
    </FormFooter>
  </form>
</template>

<script setup lang="ts">
import type { Outbound, PanelNode, Rule, RuleMatch, RuleTemplate } from '~/types/api'

const props = defineProps<{ id: number | null }>()
const emit = defineEmits<{ title: [m: { title: string, subtitle?: string }], done: [] }>()

const nodes = ref<PanelNode[]>([])
const outbounds = ref<Outbound[]>([])
const templates = ref<RuleTemplate[]>([])
const ready = ref(false)
const form = reactive({ name: '', daemon_id: null as number | null, outbound: 'direct', enabled: true, sort: 0 })
const match = reactive<RuleMatch & Record<string, unknown>>({
  domain_suffix: [], domain: [], domain_keyword: [], geosite: [], geoip: [], ip_cidr: [], port: [], protocol: [], inbound_tags: [], users: [],
})

const outboundChoices = computed(() => [...new Set(outbounds.value.filter(o => form.daemon_id === null || o.daemon_id === form.daemon_id).map(o => o.tag))])

onMounted(async () => {
  const [ns, outs, tpl] = await Promise.all([useApi<PanelNode[]>('/nodes'), useApi<Outbound[]>('/outbounds'), useApi<RuleTemplate[]>('/rules/presets')])
  nodes.value = ns
  outbounds.value = outs
  templates.value = tpl

  if (props.id) {
    const rules = await useApi<Rule[]>('/rules')
    const r = rules.find(x => x.id === props.id)
    if (r) {
      Object.assign(form, { name: r.name, daemon_id: r.daemon_id, outbound: r.outbound, enabled: r.enabled, sort: r.sort })
      Object.assign(match, { domain_suffix: [], domain: [], domain_keyword: [], geosite: [], geoip: [], ip_cidr: [], port: [], protocol: [], inbound_tags: [], users: [] }, r.match)
      emit('title', { title: r.name || 'Rule', subtitle: 'Routing rule' })
    }
  }
  else {
    emit('title', { title: 'New rule', subtitle: 'Choose what traffic goes where' })
  }
  ready.value = true
})

const checkCountry = (v: string) => (/^[a-z]{2}$/i.test(v) ? undefined : 'Use a two letter country code, like ru')
const checkDomainLike = (v: string) => (/^[a-z0-9.-]+$/i.test(v) && v.includes('.') ? undefined : 'Enter a domain, like netflix.com')

const formApi = useForm(() => (ready.value ? { ...form, match } : null), f => problems({
  outbound: checkRequired(f.outbound, 'Pick where the traffic goes'),
  match: Object.values(f.match).some(v => Array.isArray(v) ? v.length : v) ? undefined : 'Add at least one condition, or the rule would match nothing',
}))

function useTemplate(t: RuleTemplate) {
  form.name = t.label
  if (t.outbound) form.outbound = t.outbound
  Object.assign(match, { domain_suffix: [], domain: [], domain_keyword: [], geosite: [], geoip: [], ip_cidr: [], port: [], protocol: [], inbound_tags: [], users: [] }, t.match)
}

function toggleProto(p: string) {
  const cur = match.protocol ?? []
  match.protocol = cur.includes(p) ? cur.filter(x => x !== p) : [...cur, p]
}

const { loading: saving, run: save } = useAsyncAction(async () => {
  const body = { ...form, match: { ...match } }
  await useApi(props.id ? `/rules/${props.id}` : '/rules', { method: props.id ? 'PUT' : 'POST', body })
  emit('done')
}, 'Saved.', formApi)

const { run: remove } = useAsyncAction(async () => {
  await useApi(`/rules/${props.id}`, { method: 'DELETE' })
  emit('done')
}, 'Rule deleted.')
</script>

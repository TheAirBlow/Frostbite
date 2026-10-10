<template>
  <div>
    <PageHeader :title="$t('Subscriptions')" subtitle="What users' apps receive when they refresh their link.">
      <Tabs v-model="tab" :tabs="[{ id: 'settings', label: 'Settings', icon: 'fa6-solid:sliders' }, { id: 'clients', label: 'Clients', icon: 'fa6-solid:mobile-screen' }, { id: 'preview', label: 'Preview', icon: 'fa6-solid:eye' }]" />
    </PageHeader>

    <!-- settings -->
    <form v-if="tab === 'settings' && sub" class="grid gap-4 xl:grid-cols-2" @submit.prevent="saveSub()">
      <Section :title="$t('Profile')">
        <div class="flex flex-col gap-3">
          <FormField label="Title" hint="Shown by apps as the name of the profile."><input v-model="sub.title" class="input w-full"></FormField>
          <FormField label="Announcement" hint="A short message some apps show at the top."><textarea v-model="sub.announce" class="textarea w-full" rows="2" /></FormField>
          <div class="grid gap-3 sm:grid-cols-2">
            <FormField label="Support link"><input v-model="sub.support_url" type="url" class="input w-full" :placeholder="$t('https://t.me/…')"></FormField>
            <FormField label="Web page link" hint="Apps with a button for it open this."><input v-model="sub.web_page_url" type="url" class="input w-full"></FormField>
          </div>
          <FormField label="Refresh every (hours)" hint="How often apps are asked to re-fetch."><input v-model.number="sub.update_hours" type="number" min="1" class="input w-28"></FormField>
        </div>
      </Section>
      <Section :title="$t('Behaviour')">
        <div class="flex flex-col gap-1">
          <FormField label="Format when the app is unknown">
            <select v-model="sub.default_format" class="select w-full"><option value="auto">{{ $t('Guess from the app name') }}</option><option v-for="f in formats" :key="f" :value="f">{{ formatLabels[f] ?? f }}</option></select>
          </FormField>
          <ToggleRow v-model="sub.notice_profiles" label="Tell inactive users why" hint="Instead of an empty list, expired, limited and disabled users see one profile named after the reason." />
          <ToggleRow v-model="sub.hide_bridges" label="Hide relay profiles" hint="Keeps subscriptions short by leaving out hosts that go through relays." />
        </div>
      </Section>
      <Section :title="$t('User page look')" hint="What people see at /u/their-link." class="xl:col-span-2">
        <div class="grid gap-4 md:grid-cols-2">
          <div class="flex flex-col gap-3">
            <FormField label="Logo" hint="An https address, or paste an image as a data url. Empty keeps the snowflake."><input v-model="sub.logo_url" class="input w-full font-mono text-xs" :placeholder="$t('https://example.com/logo.png')"></FormField>
            <FormField label="Accent colour">
              <div class="flex items-center gap-2">
                <input type="color" class="size-9 cursor-pointer rounded-lg border-0 bg-transparent" :value="sub.accent || '#7cc8f7'" @input="sub.accent = ($event.target as HTMLInputElement).value">
                <input v-model="sub.accent" class="input input-sm w-28 font-mono" :placeholder="$t('#7cc8f7')">
                <button v-if="sub.accent" type="button" class="btn btn-ghost btn-sm" @click="sub.accent = ''">{{ $t('Reset') }}</button>
              </div>
            </FormField>
            <FormField label="Footer" hint="A line under the page: a link to your site, terms, a contact."><input v-model="sub.footer" class="input w-full" maxlength="500"></FormField>
          </div>
          <div class="bg-base-100 border-base-300 flex flex-col items-center gap-3 rounded-xl border p-5" :style="sub.accent ? { '--color-primary': sub.accent } : {}">
            <img v-if="sub.logo_url" :src="sub.logo_url" alt="" class="size-14 rounded-2xl object-contain">
            <span v-else class="grid size-14 place-items-center rounded-2xl bg-gradient-to-br from-primary/90 to-secondary/90 text-primary-content"><Icon name="fa6-solid:snowflake" size="26" /></span>
            <p class="font-display text-xl font-semibold">{{ sub.title || 'Your title' }}</p>
            <button type="button" class="btn btn-primary btn-sm">{{ $t('Add to app') }}</button>
            <p v-if="sub.footer" class="text-base-content/50 text-xs">{{ sub.footer }}</p>
          </div>
        </div>
      </Section>
      <div class="xl:col-span-2 flex justify-end"><button class="btn btn-primary" :class="{ 'btn-disabled': saving }">{{ $t('Save settings') }}</button></div>
    </form>

    <!-- clients -->
    <div v-else-if="tab === 'clients'" class="grid gap-4 xl:grid-cols-2">
      <Section :title="$t('Client rules')" hint="The first rule whose pattern matches the app's user agent decides the format.">
        <template #actions><button class="btn btn-sm" @click="newRule()"><Icon name="fa6-solid:plus" size="12" /> {{ $t('Add') }}</button></template>
        <div class="flex flex-col gap-2">
          <div v-for="r in rules ?? []" :key="r.id" class="bg-base-100 border-base-300 rounded-xl border p-3">
            <form class="grid gap-2 sm:grid-cols-12" @submit.prevent="saveRule(r)">
              <input v-model="r.name" class="input input-sm sm:col-span-3" :placeholder="$t('Name')">
              <input v-model="r.ua_regex" class="input input-sm font-mono sm:col-span-4" :placeholder="$t('clash|mihomo')" required>
              <select v-model="r.format" class="select select-sm sm:col-span-2"><option v-for="f in formats" :key="f" :value="f">{{ f }}</option></select>
              <select v-model="r.template_id" class="select select-sm sm:col-span-3"><option :value="null">{{ $t('No template') }}</option><option v-for="t in templates ?? []" :key="t.id" :value="t.id">{{ t.name }}</option></select>
              <div class="flex items-center justify-between gap-2 sm:col-span-12">
                <label class="flex items-center gap-2 text-sm"><input v-model="r.enabled" type="checkbox" class="toggle toggle-xs toggle-primary"> {{ $t('Enabled') }}</label>
                <div class="flex gap-1"><ConfirmButton type="button" class="btn btn-ghost btn-xs text-error" confirm-label="Delete?" @confirmed="removeRule(r.id)"><Icon name="fa6-solid:trash" size="11" /></ConfirmButton><button class="btn btn-xs btn-primary">{{ $t('Save') }}</button></div>
              </div>
            </form>
          </div>
          <p v-if="!rules?.length" class="text-base-content/50 text-sm">{{ $t('No custom rules. Built in detection already knows Clash, sing-box, v2rayN, Hiddify, Streisand, Happ and Shadowrocket.') }}</p>
        </div>
        <div class="bg-base-100 border-base-300 mt-4 rounded-xl border p-3">
          <p class="mb-1 text-sm font-medium">{{ $t('Try a user agent') }}</p>
          <input v-model="tryUa" class="input input-sm w-full font-mono" :placeholder="$t('ClashMeta/1.18')">
          <p v-if="tryUa" class="mt-1 text-sm">→ <span class="badge badge-primary badge-soft">{{ tryFormat }}</span></p>
        </div>
      </Section>

      <Section :title="$t('Templates')" hint="A JSON patch merged over the generated config of a format. Use it for custom DNS, rules, groups and so on.">
        <template #actions><button class="btn btn-sm" @click="editTemplate = { id: 0, name: '', format: 'singbox', patch: {} }"><Icon name="fa6-solid:plus" size="12" /> {{ $t('Add') }}</button></template>
        <div class="flex flex-col gap-2">
          <button v-for="t in templates ?? []" :key="t.id" class="bg-base-100 border-base-300 hover:border-primary/50 flex items-center gap-3 rounded-xl border p-3 text-left transition" @click="openTemplate(t)">
            <Icon name="fa6-solid:file-code" size="14" class="text-primary" />
            <div class="min-w-0 flex-1"><p class="font-medium">{{ t.name }}</p><p class="text-base-content/50 text-xs">{{ t.format }} · {{ Object.keys(t.patch).length }} keys</p></div>
          </button>
          <p v-if="!templates?.length" class="text-base-content/50 text-sm">{{ $t('No templates.') }}</p>
        </div>
      </Section>
    </div>

    <!-- preview -->
    <div v-else-if="tab === 'preview'" class="flex flex-col gap-4">
      <Section :title="$t('See what an app would get')">
        <div class="grid gap-3 md:grid-cols-4">
          <FormField label="User" class="md:col-span-2">
            <input v-model="userSearch" class="input w-full" :placeholder="$t('Search by name')" list="preview-users" @change="pickUser">
            <datalist id="preview-users"><option v-for="u in userHits" :key="u.id" :value="u.username" /></datalist>
          </FormField>
          <FormField label="Pretend to be">
            <select v-model="uaPick" class="select w-full"><option v-for="(ua, name) in uaPresets" :key="name" :value="ua">{{ name }}</option></select>
          </FormField>
          <FormField label="Force format">
            <select v-model="forceFormat" class="select w-full"><option value="">{{ $t('Auto') }}</option><option v-for="f in formats" :key="f" :value="f">{{ f }}</option></select>
          </FormField>
        </div>
        <button class="btn btn-primary btn-sm mt-3" :class="{ 'btn-disabled': !previewUser || previewing }" @click="runPreview()"><span v-if="previewing" class="loading loading-spinner loading-xs" /> {{ $t('Render') }}</button>
      </Section>

      <Section v-if="preview" :title="`Result: ${preview.format}`">
        <template #actions><CopyButton :value="preview.content" /></template>
        <dl class="text-base-content/60 mb-3 grid gap-x-4 gap-y-1 text-xs sm:grid-cols-2"><template v-for="(v, k) in preview.headers" :key="k"><dt class="font-mono">{{ k }}</dt><dd class="truncate font-mono">{{ v }}</dd></template></dl>
        <pre class="bg-base-300/60 max-h-[55vh] overflow-auto rounded-lg p-3 font-mono text-xs leading-relaxed">{{ preview.content }}</pre>
      </Section>
    </div>

    <AppModal v-if="editTemplate" :title="editTemplate.id ? 'Edit template' : 'New template'" max-width="max-w-2xl" @close="editTemplate = null">
      <form id="tpl" class="flex flex-col gap-3" @submit.prevent="saveTemplate()">
        <div class="grid gap-3 sm:grid-cols-2">
          <FormField label="Name"><input v-model="editTemplate.name" class="input w-full" required></FormField>
          <FormField label="Format"><select v-model="editTemplate.format" class="select w-full"><option v-for="f in formats" :key="f" :value="f">{{ f }}</option></select></FormField>
        </div>
        <FormField label="Patch" hint="Objects merge, arrays replace, null deletes a key."><JsonField v-model="tplPatch" :rows="12" placeholder='{ "dns": { } }' /></FormField>
      </form>
      <template #footer>
        <div class="flex items-center justify-between">
          <ConfirmButton v-if="editTemplate.id" type="button" class="btn btn-ghost text-error" confirm-label="Delete?" @confirmed="removeTemplate()">{{ $t('Delete') }}</ConfirmButton>
          <span v-else />
          <button form="tpl" class="btn btn-primary">{{ $t('Save template') }}</button>
        </div>
      </template>
    </AppModal>
  </div>
</template>

<script setup lang="ts">
import type { PanelUser, SubRule, SubSettings, SubTemplate, UserPage } from '~/types/api'

useHead({ title: 'Subscriptions' })
const tab = ref('settings')
const formats = ['links', 'raw', 'clash', 'singbox', 'xray']
const formatLabels: Record<string, string> = { links: 'Share links (base64)', raw: 'Share links (plain)', clash: 'Clash / Mihomo', singbox: 'sing-box', xray: 'Xray JSON' }

const { data: settings } = useAsyncData('settings', () => useApi<{ subscription: SubSettings }>('/settings'))
const sub = ref<SubSettings | null>(null)
watch(settings, (s) => {
  if (s && !sub.value) sub.value = { ...s.subscription }
}, { immediate: true })
const { loading: saving, run: saveSub } = useAsyncAction(async () => {
  await useApi('/settings/subscription', { method: 'PUT', body: { ...sub.value } })
}, 'Saved.')

const { data: rules, refresh: refreshRules } = useAsyncData('sub-rules', () => useApi<SubRule[]>('/sub/rules'))
const { data: templates, refresh: refreshTemplates } = useAsyncData('sub-templates', () => useApi<SubTemplate[]>('/sub/templates'))

async function newRule() {
  try {
    await useApi('/sub/rules', { method: 'POST', body: { name: 'New rule', ua_regex: 'myclient', format: 'links', enabled: true, sort: (rules.value?.length ?? 0) } })
    await refreshRules()
  }
  catch (e) {
    useToast().error(errorMessage(e))
  }
}
const { run: saveRule } = useAsyncAction(async (r: SubRule) => {
  await useApi(`/sub/rules/${r.id}`, { method: 'PUT', body: { ...r } })
  await refreshRules()
}, 'Saved.')
const { run: removeRule } = useAsyncAction(async (id: number) => {
  await useApi(`/sub/rules/${id}`, { method: 'DELETE' })
  await refreshRules()
})

const tryUa = ref('')
const tryFormat = computed(() => {
  for (const r of rules.value ?? []) {
    try {
      if (r.enabled && new RegExp(r.ua_regex, 'i').test(tryUa.value)) return r.format
    }
    catch { /* a broken pattern just never matches */ }
  }
  const ua = tryUa.value
  if (/clash|mihomo|stash|verge|flclash|koala/i.test(ua)) return 'clash'
  if (/sing-?box|sfa|sfi|sfm|karing/i.test(ua)) return 'singbox'
  return 'links'
})

const editTemplate = ref<SubTemplate | null>(null)
function openTemplate(t: SubTemplate) {
  editTemplate.value = structuredClone(toRaw(t))
}
const tplPatch = computed({
  get: () => editTemplate.value?.patch ?? null,
  set: v => editTemplate.value && (editTemplate.value.patch = v ?? {}),
})
const { run: saveTemplate } = useAsyncAction(async () => {
  const t = editTemplate.value!
  await useApi(t.id ? `/sub/templates/${t.id}` : '/sub/templates', { method: t.id ? 'PUT' : 'POST', body: { name: t.name, format: t.format, patch: t.patch } })
  editTemplate.value = null
  await refreshTemplates()
}, 'Saved.')
const { run: removeTemplate } = useAsyncAction(async () => {
  await useApi(`/sub/templates/${editTemplate.value!.id}`, { method: 'DELETE' })
  editTemplate.value = null
  await refreshTemplates()
})

const userSearch = ref('')
const searchDebounced = refDebounced(userSearch, 250)
const userHits = ref<PanelUser[]>([])
watch(searchDebounced, async (q) => {
  userHits.value = q ? (await useApi<UserPage>('/users', { query: { search: q, limit: 8 } })).items : []
})
const previewUser = ref<PanelUser | null>(null)
function pickUser() {
  previewUser.value = userHits.value.find(u => u.username === userSearch.value) ?? null
}
const uaPresets: Record<string, string> = {
  'Clash Meta': 'ClashMetaForAndroid/2.11',
  'sing-box': 'sing-box 1.12.0',
  'v2rayN': 'v2rayN/7.0',
  'Hiddify': 'HiddifyNext/2.0',
  'Shadowrocket': 'Shadowrocket/2.2',
  'curl': 'curl/8.5.0',
}
const uaPick = ref(uaPresets['Clash Meta']!)
const forceFormat = ref('')
const preview = ref<{ format: string, content: string, headers: Record<string, string> } | null>(null)
const { loading: previewing, run: runPreview } = useAsyncAction(async () => {
  preview.value = await useApi('/sub/preview', { query: { user_id: previewUser.value!.id, ua: uaPick.value, format: forceFormat.value } })
})
</script>

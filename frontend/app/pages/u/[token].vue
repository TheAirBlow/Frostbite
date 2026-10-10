<template>
  <div class="mx-auto flex max-w-2xl flex-col gap-4 px-4 py-8 sm:py-12" :style="accentStyle">
    <Skeleton v-if="pending" :rows="3" :height="140" />
    <EmptyState v-else-if="error || !data" icon="fa6-solid:link-slash" :title="t('portal.badLink')" :text="t('portal.badLinkText')" />
    <template v-else>
      <header class="flex items-center gap-3">
        <img v-if="data.brand?.logo_url" :src="data.brand.logo_url" alt="" class="size-11 rounded-2xl object-contain">
        <span v-else class="grid size-11 place-items-center rounded-2xl bg-gradient-to-br from-primary/90 to-secondary/90 text-primary-content shadow-lg shadow-primary/20"><Icon name="fa6-solid:snowflake" size="20" /></span>
        <div class="min-w-0 flex-1"><h1 class="font-display truncate text-2xl font-semibold">{{ data.title }}</h1><p class="text-base-content/60 text-sm">{{ t('portal.hello', { name: data.user.username }) }}</p></div>
        <LanguageSwitcher />
        <StatusBadge :status="data.user.status" />
      </header>

      <div v-if="data.announce" class="alert alert-info alert-soft"><Icon name="fa6-solid:bullhorn" size="14" /><span class="text-sm">{{ data.announce }}</span></div>
      <div v-if="inactive" class="alert alert-error alert-soft"><Icon name="fa6-solid:circle-exclamation" size="14" /><span class="text-sm">{{ inactive }}</span></div>

      <section class="surface flex flex-wrap items-center gap-6 p-5">
        <div class="relative grid size-32 shrink-0 place-items-center rounded-full" :style="ring">
          <div class="bg-base-200 grid size-[6.4rem] place-items-center rounded-full text-center">
            <div><p class="font-display text-3xl leading-none font-semibold">{{ data.user.traffic_limit ? `${pct}%` : '∞' }}</p><p class="text-base-content/50 mt-1 text-xs">{{ t('portal.used') }}</p></div>
          </div>
        </div>
        <dl class="grid flex-1 grid-cols-2 gap-x-6 gap-y-3 text-sm">
          <div><dt class="text-base-content/50 text-xs">{{ t('portal.traffic') }}</dt><dd class="font-medium">{{ formatBytes(data.user.traffic_used) }}<span v-if="data.user.traffic_limit" class="text-base-content/50 font-normal"> {{ t('portal.of', { limit: formatBytes(data.user.traffic_limit) }) }}</span></dd></div>
          <div><dt class="text-base-content/50 text-xs">{{ t('portal.remaining') }}</dt><dd class="font-medium">{{ data.user.traffic_limit ? formatBytes(Math.max(0, data.user.traffic_limit - data.user.traffic_used)) : t('portal.unlimited') }}</dd></div>
          <div><dt class="text-base-content/50 text-xs">{{ t('portal.validUntil') }}</dt><dd class="font-medium">{{ data.user.expire_at ? formatDate(data.user.expire_at) : data.user.status === 'on_hold' ? t('portal.startsFirstUse') : t('portal.noEnd') }}</dd></div>
          <div><dt class="text-base-content/50 text-xs">{{ t('portal.timeLeft') }}</dt><dd class="font-medium">{{ timeLeft }}</dd></div>
        </dl>
      </section>

      <section class="surface p-5">
        <h2 class="font-display text-xl font-semibold">{{ t('portal.connect') }}</h2>
        <p class="text-base-content/60 mb-3 text-sm">{{ t('portal.connectText') }}</p>
        <div class="flex flex-col gap-2">
          <div v-for="a in recommended" :key="a.id" class="bg-base-100 border-base-300 flex items-center gap-3 rounded-xl border p-3">
            <div class="min-w-0 flex-1"><p class="font-medium">{{ a.name }}</p><p class="text-base-content/50 text-xs capitalize">{{ a.platforms.join(', ') }}</p></div>
            <a :href="a.download" target="_blank" rel="noopener" class="btn btn-sm btn-ghost">{{ t('portal.getApp') }}</a>
            <a v-if="a.import" :href="deepLink(a.import)" class="btn btn-sm btn-primary"><Icon name="fa6-solid:plus" size="11" /> {{ t('portal.add') }}</a>
          </div>
        </div>
        <button v-if="others.length" class="btn btn-ghost btn-sm text-base-content/60 mt-2" @click="showAll = !showAll">{{ showAll ? t('portal.hideOthers') : t('portal.showOthers') }}</button>
        <div v-if="showAll" class="mt-2 flex flex-col gap-2">
          <div v-for="a in others" :key="a.id" class="bg-base-100 border-base-300 flex items-center gap-3 rounded-xl border p-3">
            <div class="min-w-0 flex-1"><p class="font-medium">{{ a.name }}</p><p class="text-base-content/50 text-xs capitalize">{{ a.platforms.join(', ') }}</p></div>
            <a :href="a.download" target="_blank" rel="noopener" class="btn btn-sm btn-ghost">{{ t('portal.getApp') }}</a>
            <a v-if="a.import" :href="deepLink(a.import)" class="btn btn-sm">{{ t('portal.add') }}</a>
          </div>
        </div>
      </section>

      <section class="surface p-5">
        <h2 class="font-display text-xl font-semibold">{{ t('portal.manual') }}</h2>
        <p class="text-base-content/60 mb-3 text-sm">{{ t('portal.manualText') }}</p>
        <div class="flex flex-col items-center gap-4 sm:flex-row">
          <QrCode :value="shownUrl" :size="170" class="shrink-0" />
          <div class="w-full min-w-0 flex-1">
            <div class="bg-base-100 border-base-300 flex items-center gap-1 rounded-lg border py-1 pr-1 pl-3"><span class="min-w-0 flex-1 truncate font-mono text-xs">{{ shownUrl }}</span><CopyButton :value="shownUrl" /></div>
            <FormField :label="t('portal.format')" class="mt-2"><select v-model="format" class="select select-sm w-full"><option value="">{{ t('portal.formatAuto') }}</option><option v-for="(u, f) in data.formats" :key="f" :value="f">{{ formatNames[f] ?? f }}</option></select></FormField>
          </div>
        </div>
      </section>

      <section v-if="data.links.length" class="surface p-5">
        <button class="flex w-full items-center justify-between text-left" @click="showLinks = !showLinks">
          <span class="font-display text-xl font-semibold">{{ t('portal.single') }} <span class="badge badge-sm badge-ghost align-middle">{{ data.links.length }}</span></span>
          <Icon :name="showLinks ? 'fa6-solid:chevron-up' : 'fa6-solid:chevron-down'" size="13" />
        </button>
        <div v-if="showLinks" class="mt-3 flex flex-col gap-2">
          <div v-for="l in data.links" :key="l.link" class="bg-base-100 border-base-300 flex items-center gap-3 rounded-xl border p-3">
            <span class="text-xl">{{ flag(l.country) }}</span>
            <div class="min-w-0 flex-1"><p class="truncate font-medium">{{ l.name }}</p><p class="text-base-content/50 text-xs">{{ protocolLabels[l.protocol] ?? l.protocol }}</p></div>
            <button v-if="l.config" class="btn btn-ghost btn-xs btn-square" :title="$t('.conf')" @click="downloadText(`${l.name}.conf`, l.config)"><Icon name="fa6-solid:file-arrow-down" size="13" /></button>
            <CopyButton :value="l.link" />
          </div>
        </div>
      </section>

      <section v-if="data.telegram_bot" class="surface flex items-center gap-3 p-4">
        <Icon name="fa6-brands:telegram" size="26" class="text-info shrink-0" />
        <div class="min-w-0 flex-1"><p class="font-medium">{{ t('portal.tgTitle') }}</p><p class="text-base-content/60 text-xs">{{ t('portal.tgText') }}</p></div>
        <a :href="`https://t.me/${data.telegram_bot}?start=${data.token}`" target="_blank" rel="noopener" class="btn btn-sm btn-info">{{ t('portal.tgButton') }}</a>
      </section>

      <p v-if="data.brand?.footer" class="text-base-content/50 text-center text-xs">{{ data.brand.footer }}</p>
      <footer v-if="data.support_url" class="text-center"><a :href="data.support_url" target="_blank" rel="noopener" class="btn btn-ghost btn-sm"><Icon name="fa6-solid:life-ring" size="13" /> {{ t('portal.help') }}</a></footer>
    </template>
  </div>
</template>

<script setup lang="ts">
import type { Portal, PortalApp } from '~/types/api'

definePageMeta({ layout: 'blank' })

const route = useRoute()
const { t } = useT()
const { data, pending, error } = useAsyncData(`portal-${route.params.token}`, () => useApi<Portal>(`/portal/${route.params.token}`))
useHead({ title: () => data.value?.title ?? 'Your subscription' })

const format = ref('')
// the page takes the owner's accent colour without touching anyone else's theme
const accentStyle = computed(() => (data.value?.brand?.accent ? { '--color-primary': data.value.brand.accent } : {}))
const showAll = ref(false)
const showLinks = ref(false)
const shownUrl = computed(() => (format.value ? data.value?.formats[format.value] : data.value?.sub_url) ?? '')
const formatNames: Record<string, string> = { links: 'Share links', raw: 'Plain links', clash: 'Clash / Mihomo', singbox: 'sing-box', xray: 'Xray JSON' }

const pct = computed(() => percent(data.value?.user.traffic_used ?? 0, data.value?.user.traffic_limit ?? 0))
const ring = computed(() => ({
  background: data.value?.user.traffic_limit
    ? `conic-gradient(${pct.value >= 95 ? 'var(--color-error)' : pct.value >= 80 ? 'var(--color-warning)' : 'var(--color-primary)'} ${pct.value}%, var(--color-base-300) 0)`
    : 'conic-gradient(color-mix(in oklab, var(--color-primary) 35%, transparent) 100%, transparent 0)',
}))

const timeLeft = computed(() => {
  const d = daysLeft(data.value?.user.expire_at)
  if (d === null) return '—'
  return d < 0 ? t('portal.expiredShort') : d === 0 ? t('portal.today') : t('portal.days', { n: d })
})

const reasons: Record<string, string> = { disabled: 'portal.msgDisabled', expired: 'portal.msgExpired', limited: 'portal.msgLimited' }
const inactive = computed(() => (reasons[data.value?.user.status ?? ''] ? t(reasons[data.value!.user.status]!) : ''))

const platform = computed(() => {
  const ua = import.meta.client ? navigator.userAgent.toLowerCase() : ''
  if (/iphone|ipad|ipod/.test(ua)) return 'ios'
  if (/android/.test(ua)) return 'android'
  if (/windows/.test(ua)) return 'windows'
  if (/mac/.test(ua)) return 'macos'
  if (/linux/.test(ua)) return 'linux'
  return ''
})
const recommended = computed<PortalApp[]>(() => (data.value?.apps ?? []).filter(a => !platform.value || a.platforms.includes(platform.value)))
const others = computed<PortalApp[]>(() => (data.value?.apps ?? []).filter(a => !recommended.value.includes(a)))

function deepLink(tpl: string): string {
  const url = data.value!.sub_url
  const name = data.value?.title ?? 'Frostbite'
  return tpl.replace('{url}', url).replace('{urlenc}', encodeURIComponent(url)).replace('{name}', encodeURIComponent(name)).replace('{b64}', btoa(url))
}
</script>

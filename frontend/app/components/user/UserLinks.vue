<template>
  <div class="flex flex-col gap-3">
    <Skeleton v-if="pending" :rows="4" :height="52" />
    <div v-if="data" class="surface flex flex-col gap-2 p-3">
      <div class="flex items-center gap-2">
        <Icon name="fa6-solid:rss" size="13" class="text-primary shrink-0" />
        <span class="min-w-0 flex-1 truncate font-mono text-xs">{{ subUrl }}</span>
        <button class="btn btn-ghost btn-xs btn-square" :title="$t('QR code')" @click="open = open === subUrl ? '' : subUrl"><Icon name="fa6-solid:qrcode" size="13" /></button>
        <CopyButton :value="subUrl" label="Copy subscription link" />
      </div>
      <div class="flex flex-wrap items-center gap-2 text-xs">
        <span class="text-base-content/60">{{ $t('Format') }}</span>
        <select v-model="format" class="select select-xs w-auto">
          <option value="">{{ $t('Detect from the client') }}</option>
          <option v-for="f in formats ?? []" :key="f" :value="f">{{ f }}</option>
        </select>
        <button v-if="data.links.length" class="btn btn-xs ms-auto" @click="copyAll"><Icon name="fa6-regular:copy" size="11" /> {{ $t('Copy every link') }}</button>
      </div>
      <div v-if="open === subUrl" class="mt-1 flex justify-center"><QrCode :value="subUrl" :size="200" /></div>
    </div>
    <template v-if="!pending && data?.links.length">
      <p class="text-base-content/60 text-sm">{{ $t('Import any of these on its own, or hand over the subscription link to get all of them.') }}</p>
      <div v-for="l in data.links" :key="l.link" class="surface p-3">
        <div class="flex items-center gap-3">
          <span class="text-xl">{{ flag(l.country) }}</span>
          <div class="min-w-0 flex-1">
            <p class="truncate font-medium">{{ l.name }}</p>
            <p class="flex flex-wrap items-center gap-1.5 text-xs">
              <span class="badge badge-sm badge-primary badge-soft">{{ protocolLabels[l.protocol] ?? l.protocol }}</span>
              <span v-if="l.via" class="badge badge-sm badge-accent badge-soft"><Icon name="fa6-solid:tower-broadcast" size="10" /> {{ l.via === 'turnable' ? $t('Turnable app') : $t('through Turnable') }}</span>
              <span v-if="l.bridge" class="badge badge-sm badge-secondary badge-soft"><Icon name="fa6-solid:bridge" size="10" /> {{ $t('bridge') }}</span>
              <span class="text-base-content/50">{{ l.node }}</span>
            </p>
          </div>
          <button v-if="l.config" class="btn btn-ghost btn-xs btn-square" :title="$t('Download the .conf file')" @click="downloadText(`${l.name}.conf`, l.config)"><Icon name="fa6-solid:file-arrow-down" size="13" /></button>
          <button class="btn btn-ghost btn-xs btn-square" :title="$t('QR code')" @click="open = open === l.link ? '' : l.link"><Icon name="fa6-solid:qrcode" size="13" /></button>
          <CopyButton :value="l.link" />
        </div>
        <div v-if="open === l.link" class="mt-3 flex flex-col items-center gap-2">
          <QrCode :value="l.config || l.link" :size="200" />
          <p class="text-base-content/50 max-w-full font-mono text-[11px] break-all">{{ l.link }}</p>
        </div>
      </div>
    </template>
    <EmptyState v-else-if="!pending" icon="fa6-solid:link-slash" :title="$t('No connections')" text="This user has no squad, or their squads contain no inbound. Add them on the Settings tab." />
  </div>
</template>

<script setup lang="ts">
import type { PanelUser, UserLink } from '~/types/api'

const props = defineProps<{ user: PanelUser }>()
const { data, pending } = useAsyncData(`user-links-${props.user.id}`, () => useApi<{ sub_url: string, links: UserLink[] }>(`/users/${props.user.id}/links`))
const open = ref('')
const format = ref('')
const { data: formats } = useAsyncData('sub-formats', () => useApi<string[]>('/sub/formats'))
const subUrl = computed(() => (data.value ? (format.value ? `${data.value.sub_url}/${format.value}` : data.value.sub_url) : ''))

const toast = useToast()
const { copy } = useClipboard()
async function copyAll() {
  await copy((data.value?.links ?? []).map(l => l.link).join('\n'))
  toast.info('Copied to the clipboard.')
}
</script>

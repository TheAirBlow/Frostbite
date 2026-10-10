<template>
  <div class="flex flex-col gap-3">
    <Skeleton v-if="pending" :rows="4" :height="52" />
    <template v-else-if="data?.links.length">
      <p class="text-base-content/60 text-sm">{{ $t('Import any of these on its own, or hand over the subscription link to get all of them.') }}</p>
      <div v-for="l in data.links" :key="l.link" class="surface p-3">
        <div class="flex items-center gap-3">
          <span class="text-xl">{{ flag(l.country) }}</span>
          <div class="min-w-0 flex-1">
            <p class="truncate font-medium">{{ l.name }}</p>
            <p class="flex flex-wrap items-center gap-1.5 text-xs">
              <span class="badge badge-sm badge-primary badge-soft">{{ protocolLabels[l.protocol] ?? l.protocol }}</span>
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
    <EmptyState v-else icon="fa6-solid:link-slash" :title="$t('No connections')" text="This user has no squad, or their squads contain no inbound. Add them on the Settings tab." />
  </div>
</template>

<script setup lang="ts">
import type { PanelUser, UserLink } from '~/types/api'

const props = defineProps<{ user: PanelUser }>()
const { data, pending } = useAsyncData(`user-links-${props.user.id}`, () => useApi<{ sub_url: string, links: UserLink[] }>(`/users/${props.user.id}/links`))
const open = ref('')
</script>

<template>
  <div class="flex flex-col gap-3">
    <div class="alert alert-warning alert-soft text-sm">
      <Icon name="fa6-solid:key" size="14" />
      <span>{{ $t('The token is shown only once. Copy the command now, or you will have to make a new one.') }}</span>
    </div>

    <Tabs v-model="tab" :tabs="[{ id: 'docker', label: 'Docker' }, { id: 'env', label: '.env file' }, { id: 'raw', label: 'Token only' }]" />

    <template v-if="tab === 'docker'">
      <p class="text-base-content/60 text-sm">{{ $t('Run this on the node. It needs Docker with the compose plugin.') }}</p>
      <div class="relative">
        <pre class="bg-base-300/60 overflow-x-auto rounded-lg p-3 pr-10 font-mono text-xs break-all whitespace-pre-wrap">{{ enrollment.command }}</pre>
        <CopyButton :value="enrollment.command" class="absolute top-2 right-2" />
      </div>
    </template>
    <template v-else-if="tab === 'env'">
      <p class="text-base-content/60 text-sm">{{ $t('Put this in .env next to the node\'s docker-compose.yml, then start the {kind} profile.', { kind }) }}</p>
      <div class="relative">
        <pre class="bg-base-300/60 overflow-x-auto rounded-lg p-3 pr-10 font-mono text-xs break-all whitespace-pre-wrap">{{ enrollment.env }}</pre>
        <CopyButton :value="enrollment.env" class="absolute top-2 right-2" />
      </div>
      <pre class="bg-base-300/60 rounded-lg p-3 font-mono text-xs">docker compose --profile {{ kind }} up -d</pre>
    </template>
    <template v-else>
      <p class="text-base-content/60 text-sm">{{ $t('For running the agent yourself: set FROSTBITE_PANEL_URL and FROSTBITE_TOKEN.') }}</p>
      <div class="bg-base-300/60 flex items-center gap-2 rounded-lg p-3">
        <span class="min-w-0 flex-1 font-mono text-xs break-all">{{ enrollment.token }}</span>
        <CopyButton :value="enrollment.token" />
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import type { Enrollment } from '~/types/api'

defineProps<{ enrollment: Enrollment, kind: string }>()
const tab = ref('docker')
</script>

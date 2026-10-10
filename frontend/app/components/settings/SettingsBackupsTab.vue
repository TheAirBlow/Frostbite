<template>
  <div class="flex max-w-3xl flex-col gap-5">
    <Section :title="$t('Back up')" hint="Everything except sessions, tokens and the audit log: nodes, daemons, inbounds, users, plans, settings and admin accounts.">
      <div class="flex flex-wrap gap-2">
        <a href="/api/backup/download" class="btn btn-primary btn-sm"><Icon name="fa6-solid:download" size="12" /> {{ $t('Download a backup') }}</a>
        <a href="/api/backup/download?history=1" class="btn btn-sm"><Icon name="fa6-solid:download" size="12" /> {{ $t('With traffic history') }}</a>
        <button class="btn btn-sm" :class="{ 'btn-disabled': creating }" @click="create()"><Icon name="fa6-solid:floppy-disk" size="12" /> {{ $t('Save one on the server') }}</button>
      </div>
    </Section>

    <Section :title="$t('On the server')">
      <Skeleton v-if="!files" :rows="2" :height="44" />
      <div v-else-if="files.length" class="flex flex-col gap-2">
        <div v-for="f in files" :key="f.name" class="bg-base-100 border-base-300 flex items-center gap-3 rounded-xl border p-3">
          <Icon name="fa6-solid:box-archive" size="14" class="text-base-content/50" />
          <div class="min-w-0 flex-1"><p class="truncate font-mono text-xs">{{ f.name }}</p><p class="text-base-content/50 text-xs">{{ formatDateTime(f.created) }} · {{ formatBytes(f.size) }}</p></div>
          <a :href="`/api/backup/files/${f.name}`" class="btn btn-ghost btn-xs" download><Icon name="fa6-solid:download" size="12" /></a>
          <ConfirmButton class="btn btn-ghost btn-xs text-error" confirm-label="Delete?" @confirmed="remove(f.name)"><Icon name="fa6-solid:trash" size="12" /></ConfirmButton>
        </div>
      </div>
      <p v-else class="text-base-content/50 text-sm">{{ $t('None yet.') }}</p>
    </Section>

    <Section v-if="schedule" :title="$t('Automatic backups')">
      <form class="flex flex-col gap-3" @submit.prevent="saveSchedule()">
        <ToggleRow v-model="schedule.enabled" label="Back up on a schedule" />
        <div class="grid gap-3 sm:grid-cols-2">
          <FormField label="Every (hours)"><input v-model.number="schedule.interval_hours" type="number" min="1" class="input w-full"></FormField>
          <FormField label="Keep the newest"><input v-model.number="schedule.keep" type="number" min="1" class="input w-full"></FormField>
        </div>
        <ToggleRow v-model="schedule.history" label="Include traffic history" hint="Makes files larger on busy panels." />
        <button class="btn btn-primary btn-sm self-end">{{ $t('Save schedule') }}</button>
      </form>
    </Section>

    <Section :title="$t('Restore')" hint="Replaces everything with the contents of a backup file.">
      <div class="alert alert-warning alert-soft mb-3 text-sm"><Icon name="fa6-solid:triangle-exclamation" size="14" /><span>{{ $t('Current data is overwritten and everyone is signed out, you included. Sign in with an account from the backup afterwards.') }}</span></div>
      <input ref="picker" type="file" accept=".gz,.json,application/gzip,application/json" class="file-input file-input-sm w-full" @change="file = ($event.target as HTMLInputElement).files?.[0] ?? null">
      <ConfirmButton class="btn btn-error btn-sm mt-3" :disabled="!file || restoring" confirm-label="Overwrite everything?" @confirmed="restore()">
        <span v-if="restoring" class="loading loading-spinner loading-xs" /> {{ $t('Restore from this file') }}
      </ConfirmButton>
    </Section>
  </div>
</template>

<script setup lang="ts">
import type { BackupFile, BackupSchedule } from '~/types/api'

const { data: files, refresh } = useAsyncData('backup-files', () => useApi<BackupFile[]>('/backup/files'))
const schedule = ref<BackupSchedule | null>(null)
onMounted(async () => {
  schedule.value = await useApi<BackupSchedule>('/backup/schedule')
})

const file = ref<File | null>(null)

const { loading: creating, run: create } = useAsyncAction(async () => {
  await useApi('/backup/files', { method: 'POST' })
  await refresh()
}, 'Backup saved.')

const { run: remove } = useAsyncAction(async (name: string) => {
  await useApi(`/backup/files/${name}`, { method: 'DELETE' })
  await refresh()
}, 'Deleted.')

const { run: saveSchedule } = useAsyncAction(async () => {
  schedule.value = await useApi<BackupSchedule>('/backup/schedule', { method: 'PUT', body: { ...schedule.value } })
}, 'Saved.')

const { loading: restoring, run: restore } = useAsyncAction(async () => {
  try {
    await $fetch('/api/backup/restore', { method: 'POST', body: file.value, headers: { 'Content-Type': 'application/octet-stream' } })
  }
  catch (e) {
    const err = e as { data?: { detail?: string } }
    throw new ApiError(0, err.data?.detail ?? 'The restore failed.')
  }
  // sessions were part of what got replaced
  window.location.href = '/login'
})
</script>

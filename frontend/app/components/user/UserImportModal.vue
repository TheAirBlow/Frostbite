<template>
  <AppModal :title="$t('Import users')" subtitle="Bring people over from Hiddify, Marzban, 3x-ui, Remnawave or a spreadsheet." max-width="max-w-3xl" @close="modal.close">
    <div v-if="!report || report.dry_run" class="flex flex-col gap-4">
      <Segmented v-model="source" :options="[{ value: 'text', label: 'CSV or JSON', icon: 'fa6-solid:file-lines' }, { value: 'db', label: 'Panel database', icon: 'fa6-solid:database' }]" />

      <template v-if="source === 'db'">
        <p class="text-base-content/60 text-sm">
          {{ $t('Upload the database file of 3x-ui (x-ui.db), Marzban (db.sqlite3) or Hiddify (hiddifypanel.db). It is only read, and the panel is recognised on its own. UUIDs, passwords, limits, usage, expiry and "starts at first use" carry over. Work on a copy if the old panel is still running.') }}
        </p>
        <input type="file" accept=".db,.sqlite,.sqlite3,application/vnd.sqlite3,application/octet-stream" class="file-input file-input-sm w-full" @change="dbFile = ($event.target as HTMLInputElement).files?.[0] ?? null; report = null">
        <p v-if="report?.panel" class="text-sm"><Icon name="fa6-solid:circle-check" size="13" class="text-success" /> {{ $t('Recognised a {panel} database.', { panel: report.panel }) }}</p>
      </template>

      <p v-else class="text-base-content/60 text-sm">
        {{ $t('Paste or upload a CSV or JSON list. Column names are matched loosely (username, name, email, uuid, traffic_limit, usage_limit_GB, used_traffic, expire, package_days, note, tags, telegram_id, enable and what those panels call them). Existing credentials are kept, so users\' apps keep working after you move the nodes.') }}
      </p>
      <template v-if="source === 'text'">
        <input type="file" accept=".csv,.json,text/csv,application/json,text/plain" class="file-input file-input-sm w-full" @change="load">
        <textarea v-model="text" class="textarea w-full font-mono text-xs" rows="8" spellcheck="false" placeholder="username,uuid,traffic_gb,expire&#10;alice,,50,2027-01-31" />
      </template>

      <Skeleton v-if="!squads" :rows="1" />
      <FormField v-else label="Add them to squads">
        <div class="flex flex-wrap gap-1.5">
          <button v-for="s in squads" :key="s.id" type="button" class="btn btn-sm rounded-full" :class="squadIds.includes(s.id) ? 'btn-primary' : 'btn-ghost bg-base-200'" @click="squadIds = squadIds.includes(s.id) ? squadIds.filter(x => x !== s.id) : [...squadIds, s.id]">{{ s.name }}</button>
        </div>
      </FormField>

      <div v-if="report" class="surface p-3">
        <p class="text-sm"><b>{{ report.created }}</b> user{{ report.created === 1 ? '' : 's' }} would be created<template v-if="report.problems.length">, <b>{{ report.problems.length }}</b> {{ $t('skipped') }}</template>.</p>
        <ul v-if="report.problems.length" class="text-warning mt-2 max-h-40 list-disc overflow-y-auto pl-5 text-xs"><li v-for="(p, i) in report.problems" :key="i">{{ p.line ? `row ${p.line}` : '' }} {{ p.username }} {{ p.reason }}</li></ul>
        <table v-if="report.sample.length" class="table table-xs mt-2"><thead><tr><th>{{ $t('User') }}</th><th>{{ $t('Limit') }}</th><th>{{ $t('Used') }}</th><th>{{ $t('Expires') }}</th></tr></thead>
          <tbody><tr v-for="r in report.sample" :key="r.username"><td>{{ r.username }}</td><td>{{ r.traffic_limit ? formatBytes(r.traffic_limit) : '∞' }}</td><td>{{ formatBytes(r.traffic_used) }}</td><td>{{ r.expire_at ? formatDate(r.expire_at) : '—' }}</td></tr></tbody></table>
      </div>
    </div>

    <div v-else class="flex flex-col items-center gap-3 py-6 text-center">
      <span class="bg-success/15 text-success grid size-14 place-items-center rounded-2xl"><Icon name="fa6-solid:check" size="24" /></span>
      <p class="font-display text-xl font-semibold">{{ report.created }} users imported</p>
      <ul v-if="report.problems.length" class="text-warning max-h-40 list-disc overflow-y-auto pl-5 text-left text-xs"><li v-for="(p, i) in report.problems" :key="i">{{ p.line ? `row ${p.line}` : '' }} {{ p.username }} {{ p.reason }}</li></ul>
      <button class="btn btn-primary btn-sm" @click="modal.close()">{{ $t('Done') }}</button>
    </div>

    <template v-if="!report || report.dry_run" #footer>
      <div class="flex justify-end gap-2">
        <button class="btn" :class="{ 'btn-disabled': !ready || working }" @click="run(true)">{{ $t('Check first') }}</button>
        <button class="btn btn-primary" :class="{ 'btn-disabled': !report || !report.created || working }" @click="run(false)"><span v-if="working" class="loading loading-spinner loading-xs" /> Import {{ report?.created ?? '' }}</button>
      </div>
    </template>
  </AppModal>
</template>

<script setup lang="ts">
import type { ImportReport, Squad } from '~/types/api'

const modal = useDrawer()
const { data: squads } = useAsyncData('squads', () => useApi<Squad[]>('/squads'))
const source = ref('text')
const dbFile = ref<File | null>(null)
const text = ref('')
const squadIds = ref<number[]>([])
const report = ref<ImportReport | null>(null)

watch(squads, (s) => {
  if (s?.length === 1 && !squadIds.value.length) squadIds.value = [s[0]!.id]
}, { immediate: true })
// a changed list invalidates the last check
watch(text, () => (report.value = null))

async function load(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0]
  if (f) text.value = await f.text()
}

const ready = computed(() => (source.value === 'db' ? !!dbFile.value : !!text.value.trim()))

const { loading: working, run } = useAsyncAction(async (dry: boolean) => {
  if (source.value === 'db') {
    try {
      report.value = await $fetch<ImportReport>('/api/users/import-db', {
        method: 'POST', body: dbFile.value, headers: { 'Content-Type': 'application/octet-stream' },
        query: { dry_run: dry ? '1' : '0', squads: squadIds.value.join(',') },
      })
    }
    catch (e) {
      const err = e as { data?: { detail?: string } }
      throw new ApiError(0, err.data?.detail ?? 'The file could not be imported.')
    }
  }
  else {
    report.value = await useApi<ImportReport>('/users/import', { method: 'POST', body: { data: text.value, squad_ids: squadIds.value, dry_run: dry } })
  }
  if (!dry) await refreshNuxtData('users')
})
</script>

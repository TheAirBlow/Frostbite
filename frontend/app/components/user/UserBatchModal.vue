<template>
  <AppModal :title="$t('Create many users')" subtitle="Names are the prefix plus a number." max-width="max-w-2xl" @close="modal.close">
    <form id="user-batch" class="flex flex-col gap-3" @submit.prevent="submit">
      <div class="grid gap-3 sm:grid-cols-3">
        <FormField label="Prefix">
          <input v-model="prefix" class="input w-full" :placeholder="$t('trial-')" required>
        </FormField>
        <FormField label="How many">
          <input v-model.number="count" type="number" min="1" max="1000" class="input w-full" required>
        </FormField>
        <FormField label="Start at">
          <input v-model.number="start" type="number" min="0" class="input w-full">
        </FormField>
      </div>
      <p class="text-base-content/60 text-sm">
        {{ $t('Creates {first} … {last} with the settings below.', { first: `${prefix}${start}`, last: `${prefix}${start + Math.max(count, 1) - 1}` }) }}
      </p>
      <div class="divider my-0" />
      <Skeleton v-if="!plans || !squads" :rows="3" />
      <UserForm v-else v-model="form" mode="create" :plans="plans" :squads="squads" />
    </form>

    <div v-if="result" class="surface mt-4 p-3">
      <div class="mb-2 flex items-center justify-between">
        <p class="text-sm font-medium">{{ result.length }} subscription links</p>
        <div class="flex gap-1">
          <button class="btn btn-xs" @click="copyAll"><Icon name="fa6-regular:copy" size="11" /> {{ $t('Copy all') }}</button>
          <button class="btn btn-xs" @click="downloadCsv"><Icon name="fa6-solid:download" size="11" /> CSV</button>
        </div>
      </div>
      <textarea class="textarea textarea-sm w-full font-mono text-xs" rows="5" readonly :value="result.map(r => r.link).join('\n')" />
    </div>

    <template #footer>
      <div class="flex justify-end">
        <button form="user-batch" class="btn btn-primary" :class="{ 'btn-disabled': saving }">
          <span v-if="saving" class="loading loading-spinner loading-xs" /> Create {{ count }} users
        </button>
      </div>
    </template>
  </AppModal>
</template>

<script setup lang="ts">
import type { PanelUser, Plan, Squad } from '~/types/api'

const modal = useDrawer()
const toast = useToast()
const { data: plans } = useAsyncData('plans', () => useApi<Plan[]>('/plans'))
const { data: squads } = useAsyncData('squads', () => useApi<Squad[]>('/squads'))

const prefix = ref('user-')
const count = ref(10)
const start = ref(1)
const form = ref(emptyUserForm())
const result = ref<{ name: string, link: string }[] | null>(null)

const { loading: saving, run: submit } = useAsyncAction(async () => {
  const res = await useApi<{ users: PanelUser[], links: string[] }>('/users/batch', {
    method: 'POST',
    body: { ...createBody(form.value), prefix: prefix.value, count: count.value, start: start.value },
  })
  result.value = res.users.map((u, i) => ({ name: u.username, link: res.links[i]! }))
  await refreshNuxtData('users')
}, 'Users created.')

const { copy } = useClipboard()
async function copyAll() {
  await copy(result.value!.map(r => r.link).join('\n'))
  toast.info('Links copied.')
}

function downloadCsv() {
  const csv = 'username,subscription\n' + result.value!.map(r => `${r.name},${r.link}`).join('\n')
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
  a.download = `${prefix.value}users.csv`
  a.click()
  URL.revokeObjectURL(a.href)
}
</script>

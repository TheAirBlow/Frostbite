<template>
  <AppModal :title="$t('New user')" subtitle="They get a subscription link as soon as you save." max-width="max-w-2xl" @close="modal.close">
    <form id="user-create" novalidate @submit.prevent="submit()">
      <Skeleton v-if="!plans || !squads" :rows="4" />
      <UserForm v-else v-model="form" mode="create" :plans="plans" :squads="squads" />
    </form>
    <template #footer>
      <FormBanner class="mb-2" />
      <div class="flex items-center justify-between gap-2">
        <button type="button" class="btn btn-ghost btn-sm" @click="modal.open('user-batch')">
          <Icon name="fa6-solid:users-line" size="13" /> {{ $t('Create many at once') }}
        </button>
        <button form="user-create" class="btn btn-primary" :disabled="saving">
          <span v-if="saving" class="loading loading-spinner loading-xs" /> {{ $t('Create user') }}
        </button>
      </div>
    </template>
  </AppModal>
</template>

<script setup lang="ts">
import type { PanelUser, Plan, Squad } from '~/types/api'

const modal = useDrawer()
const side = useSideDrawer()
const { data: plans } = useAsyncData('plans', () => useApi<Plan[]>('/plans'))
const { data: squads } = useAsyncData('squads', () => useApi<Squad[]>('/squads'))

const form = ref(emptyUserForm())
const formApi = useForm(form, f => userRules(f, 'create'))
// a fresh panel has one squad at most, so just preselect it
watch(squads, (s) => {
  if (s?.length === 1 && !form.value.squad_ids.length) form.value.squad_ids = [s[0]!.id]
}, { immediate: true })

const { loading: saving, run: submit } = useAsyncAction(async () => {
  const u = await useApi<PanelUser>('/users', { method: 'POST', body: createBody(form.value) })
  await refreshNuxtData('users')
  modal.close()
  side.open('user', u.id)
}, 'User created.', formApi)
</script>

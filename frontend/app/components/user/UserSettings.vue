<template>
  <form class="flex flex-col gap-4" @submit.prevent="save">
    <Skeleton v-if="!plans || !squads" :rows="4" />
    <UserForm v-else v-model="form" mode="edit" :plans="plans" :squads="squads" :current-status="user.status" />
    <div class="bg-base-100 border-base-300 sticky bottom-0 -mx-4 -mb-4 flex justify-end gap-2 border-t p-3">
      <button type="button" class="btn btn-ghost" :disabled="!dirty" @click="reset">{{ $t('Revert') }}</button>
      <button class="btn btn-primary" :class="{ 'btn-disabled': saving || !dirty }">
        <span v-if="saving" class="loading loading-spinner loading-xs" /> {{ $t('Save changes') }}
      </button>
    </div>
  </form>
</template>

<script setup lang="ts">
import type { PanelUser, Plan, Squad } from '~/types/api'

const props = defineProps<{ user: PanelUser }>()
const emit = defineEmits<{ changed: [] }>()

const { data: plans } = useAsyncData('plans', () => useApi<Plan[]>('/plans'))
const { data: squads } = useAsyncData('squads', () => useApi<Squad[]>('/squads'))

const form = ref(formFromUser(props.user))
const dirty = computed(() => JSON.stringify(form.value) !== JSON.stringify(formFromUser(props.user)))

// follow changes made elsewhere, unless there is unsaved work here
watch(() => props.user, (u) => {
  if (!dirty.value) form.value = formFromUser(u)
})

function reset() {
  form.value = formFromUser(props.user)
}

const { loading: saving, run: save } = useAsyncAction(async () => {
  await useApi(`/users/${props.user.id}`, { method: 'PUT', body: updateBody(form.value) })
  emit('changed')
}, 'Saved.')
</script>

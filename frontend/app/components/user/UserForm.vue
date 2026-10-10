<template>
  <div class="flex flex-col gap-3">
    <FormField label="Username">
      <div class="join w-full">
        <input v-model="form.username" class="input join-item w-full" :placeholder="$t('alice')" autocomplete="off" required>
        <button v-if="mode === 'create'" type="button" class="btn join-item" :title="$t('Pick a random name')" @click="form.username = randomName()">
          <Icon name="fa6-solid:dice" size="14" />
        </button>
      </div>
    </FormField>

    <FormField v-if="mode === 'create' && plans.length" label="Start from a plan" hint="Fills in the fields below. You can still change them.">
      <select class="select w-full" :value="form.plan_id ?? ''" @change="pickPlan(($event.target as HTMLSelectElement).value)">
        <option value="">{{ $t('No plan') }}</option>
        <option v-for="p in plans" :key="p.id" :value="p.id">{{ p.name }}</option>
      </select>
    </FormField>

    <div v-if="mode === 'edit'" class="flex flex-col gap-1">
      <p class="fieldset-legend">{{ $t('Status') }}</p>
      <Segmented v-model="form.status" :options="statusOptions" />
      <p v-if="stateNote" class="text-base-content/60 text-xs">{{ stateNote }}</p>
    </div>

    <FormField label="Traffic limit" hint="Counted against the node multipliers.">
      <ByteInput v-model="form.traffic_limit" />
    </FormField>

    <div class="grid gap-3 sm:grid-cols-2">
      <FormField label="Resets">
        <select v-model="form.reset_strategy" class="select w-full">
          <option v-for="(label, key) in resetLabels" :key="key" :value="key">{{ label }}</option>
        </select>
      </FormField>

      <FormField v-if="mode === 'create'" label="Valid for">
        <div class="flex items-center gap-2">
          <input v-model.number="form.duration_days" type="number" min="0" class="input w-full" :placeholder="$t('0 = never expires')" :disabled="!!form.expire_at">
          <span class="text-base-content/60 text-sm">{{ $t('days') }}</span>
        </div>
        <div class="mt-1 flex flex-wrap gap-1">
          <button v-for="d in [7, 30, 90, 180, 365]" :key="d" type="button" class="btn btn-xs btn-ghost bg-base-200 rounded-full" @click="form.duration_days = d; form.expire_at = ''">{{ d }}d</button>
          <button type="button" class="btn btn-xs btn-ghost bg-base-200 rounded-full" @click="form.duration_days = 0; form.expire_at = ''">{{ $t('never') }}</button>
        </div>
      </FormField>

      <FormField v-else label="Expires on">
        <div class="flex items-center gap-2">
          <input v-model="form.expire_at" type="date" class="input w-full">
          <button v-if="form.expire_at" type="button" class="btn btn-ghost btn-sm" @click="form.expire_at = ''">{{ $t('Never') }}</button>
        </div>
      </FormField>
    </div>

    <ToggleRow v-if="mode === 'create'" v-model="form.start_on_first_use" label="Start the clock on first use" hint="The user stays on hold and the validity only starts counting at their first connection." />

    <FormField v-if="form.status === 'on_hold' && mode === 'edit'" label="Days to run after first use">
      <input v-model.number="form.on_hold_days" type="number" min="0" class="input w-full">
    </FormField>

    <FormField label="Squads" hint="Which inbounds this user can connect to.">
      <div v-if="squads.length" class="flex flex-wrap gap-1.5">
        <button v-for="s in squads" :key="s.id" type="button" class="btn btn-sm rounded-full" :class="form.squad_ids.includes(s.id) ? 'btn-primary' : 'btn-ghost bg-base-200'" @click="toggleSquad(s.id)">
          <Icon :name="form.squad_ids.includes(s.id) ? 'fa6-solid:check' : 'fa6-solid:plus'" size="10" /> {{ s.name }}
        </button>
      </div>
      <p v-else class="text-warning text-sm">{{ $t('There are no squads yet, so this user would get nothing.') }} <NuxtLink to="/access" class="link">{{ $t('Create one') }}</NuxtLink>.</p>
    </FormField>

    <FormField label="Tags">
      <ChipInput v-model="form.tags" :placeholder="$t('Add tags, press enter')" />
    </FormField>

    <FormField label="Note">
      <textarea v-model="form.note" class="textarea w-full" rows="2" :placeholder="$t('Anything worth remembering')" />
    </FormField>

    <Advanced :title="$t('Limits and contacts')">
      <div class="grid gap-3 sm:grid-cols-2">
        <FormField label="Device limit" hint="Counted by the device id apps send. 0 is unlimited.">
          <input v-model.number="form.device_limit" type="number" min="0" class="input w-full">
        </FormField>
        <FormField label="Simultaneous IPs" hint="Going over cuts the user off for a few minutes. 0 is unlimited.">
          <input v-model.number="form.ip_limit" type="number" min="0" class="input w-full">
        </FormField>
        <FormField label="Email">
          <input v-model="form.email" type="email" class="input w-full">
        </FormField>
        <FormField label="Telegram ID">
          <input v-model.number="form.telegram_id" type="number" class="input w-full" :placeholder="$t('optional')">
        </FormField>
      </div>
    </Advanced>
  </div>
</template>

<script setup lang="ts">
import type { Plan, Squad } from '~/types/api'
import type { UserFormState } from '~/utils/userForm'

const props = defineProps<{ mode: 'create' | 'edit', plans: Plan[], squads: Squad[], currentStatus?: string }>()
const form = defineModel<UserFormState>({ required: true })

const statusOptions = [
  { value: 'active', label: 'Active' },
  { value: 'on_hold', label: 'On hold' },
  { value: 'disabled', label: 'Disabled' },
]

const stateNote = computed(() => {
  if (props.currentStatus === 'limited') return 'Hit the traffic limit. Raise the limit or reset the traffic to bring them back.'
  if (props.currentStatus === 'expired') return 'Expired. Pick a new date to bring them back.'
  return ''
})

function pickPlan(value: string) {
  const plan = props.plans.find(p => p.id === Number(value))
  form.value.plan_id = plan?.id ?? null
  if (plan) applyPlan(form.value, plan)
}

function toggleSquad(id: number) {
  const ids = form.value.squad_ids
  form.value.squad_ids = ids.includes(id) ? ids.filter(x => x !== id) : [...ids, id]
}
</script>

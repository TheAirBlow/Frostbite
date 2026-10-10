<template>
  <div>
    <PageHeader :title="$t('Squads & plans')" subtitle="Who can reach which inbounds, and the ready made packages you sell or hand out.">
      <Tabs v-model="tab" :tabs="[{ id: 'squads', label: 'Squads', icon: 'fa6-solid:layer-group' }, { id: 'plans', label: 'Plans', icon: 'fa6-solid:box' }]" />
    </PageHeader>

    <template v-if="tab === 'squads'">
      <div class="mb-3 flex items-center justify-between gap-2">
        <p class="text-base-content/60 text-sm">{{ $t('A squad is a bundle of inbounds. Put users in squads to decide where they can connect.') }}</p>
        <button class="btn btn-primary btn-sm" @click="side.open('squad')"><Icon name="fa6-solid:plus" size="12" /> {{ $t('New squad') }}</button>
      </div>
      <Skeleton v-if="!squads" :rows="2" :height="120" />
      <div v-else-if="squads.length" class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <button v-for="s in squads" :key="s.id" class="surface hover:border-primary/50 flex flex-col gap-3 p-4 text-left transition" @click="side.open('squad', s.id)">
          <div class="flex items-start justify-between gap-2">
            <div class="min-w-0"><p class="font-display truncate text-xl font-semibold">{{ s.name }}</p><p v-if="s.note" class="text-base-content/50 truncate text-xs">{{ s.note }}</p></div>
            <span class="badge badge-primary badge-soft whitespace-nowrap"><Icon name="fa6-solid:users" size="10" /> {{ s.users }}</span>
          </div>
          <div class="flex flex-wrap gap-1.5">
            <span v-for="i in inboundsOf(s).slice(0, 6)" :key="i.id" class="badge badge-sm badge-ghost">{{ i.remark || i.tag }}</span>
            <span v-if="s.inbound_ids.length > 6" class="badge badge-sm badge-ghost">+{{ s.inbound_ids.length - 6 }}</span>
            <span v-if="!s.inbound_ids.length" class="text-warning text-xs">{{ $t('No inbounds, so members get nothing.') }}</span>
          </div>
        </button>
      </div>
      <div v-else class="surface"><EmptyState icon="fa6-solid:layer-group" :title="$t('No squads yet')" text="Create one with the inbounds you want to give out. Most setups need only one or two."><button class="btn btn-primary btn-sm" @click="side.open('squad')">{{ $t('New squad') }}</button></EmptyState></div>
    </template>

    <template v-else>
      <div class="mb-3 flex items-center justify-between gap-2">
        <p class="text-base-content/60 text-sm">{{ $t('A plan fills in a new user\'s limits, validity and squads in one click.') }}</p>
        <button class="btn btn-primary btn-sm" @click="side.open('plan')"><Icon name="fa6-solid:plus" size="12" /> {{ $t('New plan') }}</button>
      </div>
      <Skeleton v-if="!plans" :rows="2" :height="120" />
      <div v-else-if="plans.length" class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <button v-for="p in plans" :key="p.id" class="surface hover:border-primary/50 flex flex-col gap-2 p-4 text-left transition" @click="side.open('plan', p.id)">
          <p class="font-display text-xl font-semibold">{{ p.name }}</p>
          <p class="text-2xl font-semibold">{{ p.traffic_limit ? formatBytes(p.traffic_limit, 0) : 'Unlimited' }}</p>
          <ul class="text-base-content/60 text-sm">
            <li>{{ p.duration_days ? `${p.duration_days} days` : 'Never expires' }}<template v-if="p.start_on_first_use"> {{ $t('· starts at first use') }}</template></li>
            <li v-if="p.reset_strategy !== 'none'">Resets {{ resetLabels[p.reset_strategy]?.toLowerCase() }}</li>
            <li v-if="p.device_limit">{{ p.device_limit }} devices</li>
            <li>{{ p.squad_ids.length }} squad{{ p.squad_ids.length === 1 ? '' : 's' }}</li>
          </ul>
        </button>
      </div>
      <div v-else class="surface"><EmptyState icon="fa6-solid:box" :title="$t('No plans yet')" text="Plans are optional. They save typing when you create many similar users."><button class="btn btn-primary btn-sm" @click="side.open('plan')">{{ $t('New plan') }}</button></EmptyState></div>
    </template>
  </div>
</template>

<script setup lang="ts">
import type { Inbound, Plan, Squad } from '~/types/api'

useHead({ title: 'Squads & plans' })
const route = useRoute()
const side = useSideDrawer()
const tab = ref('squads')

const { data: squads, refresh: r1 } = useAsyncData('squads', () => useApi<Squad[]>('/squads'))
const { data: plans, refresh: r2 } = useAsyncData('plans', () => useApi<Plan[]>('/plans'))
const { data: inbounds } = useAsyncData('inbounds', () => useApi<Inbound[]>('/inbounds'))

watch(() => route.query.drawer, (d) => {
  if (!d) {
    r1()
    r2()
  }
})

const inboundsOf = (s: Squad) => (inbounds.value ?? []).filter(i => s.inbound_ids.includes(i.id))
</script>

<template>
  <section class="surface flex flex-col gap-3 p-4">
    <header class="flex items-start justify-between gap-3">
      <div>
        <h4 class="text-base-content/70 text-sm font-semibold tracking-wide uppercase">{{ $t('Destinations') }}</h4>
        <p class="text-base-content/60 mt-0.5 text-xs">{{ $t('Where the tunnel can lead. Every user of this inbound may use all of them, and their app picks one by its id. Give each its own address, such as a WireGuard inbound and a web server.') }}</p>
      </div>
      <button type="button" class="btn btn-sm shrink-0" @click="add"><Icon name="fa6-solid:plus" size="11" /> {{ $t('Add') }}</button>
    </header>

    <p v-if="!model.length" class="text-warning text-sm" data-field="options.t_routes" :data-field-error="rootError ? '' : undefined">{{ rootError ? $t(rootError) : $t('No destinations yet. Without one the tunnel leads nowhere.') }}</p>

    <article v-for="(r, i) in model" :key="i" class="bg-base-100 border-base-300 flex flex-col gap-3 rounded-xl border p-3">
      <div class="flex items-center gap-2">
        <span class="badge badge-primary badge-soft font-mono">{{ r.id || '?' }}</span>
        <span class="text-base-content/60 min-w-0 flex-1 truncate text-sm">{{ r.name || r.target || $t('New destination') }}</span>
        <button type="button" class="btn btn-ghost btn-xs btn-square text-error" :disabled="model.length === 1" :title="model.length === 1 ? $t('A tunnel needs at least one destination') : $t('Remove')" :aria-label="$t('Remove')" @click="remove(i)">
          <Icon name="fa6-solid:trash" size="12" />
        </button>
      </div>

      <div class="grid gap-3 sm:grid-cols-5">
        <FormField class="sm:col-span-3" label="Destination" :name="`options.t_routes.${i}.target`" hint="An IP address and port, usually an inbound on this node." required>
          <input v-model="r.target" class="input w-full font-mono" placeholder="127.0.0.1:51820" inputmode="url" autocomplete="off">
        </FormField>
        <FormField class="sm:col-span-2" label="Network" :name="`options.t_routes.${i}.socket`" required>
          <select v-model="r.socket" class="select w-full">
            <option value="udp">{{ $t('UDP') }}</option>
            <option value="tcp">{{ $t('TCP') }}</option>
          </select>
        </FormField>
      </div>

      <Advanced :title="$t('Id, name and tunnel options')">
        <div class="grid gap-3 sm:grid-cols-2">
          <FormField label="Id" :name="`options.t_routes.${i}.id`" hint="Apps refer to the destination by this. Lowercase letters, digits, - and _." required>
            <input :value="r.id" class="input w-full font-mono" placeholder="wg" autocomplete="off" @input="r.id = ($event.target as HTMLInputElement).value.toLowerCase()">
          </FormField>
          <FormField label="Name" :name="`options.t_routes.${i}.name`" hint="Shown in the app. Empty uses the user's name.">
            <input v-model="r.name" class="input w-full">
          </FormField>
          <FormField label="Transport" :name="`options.t_routes.${i}.transport`" hint="How packets are carried inside the tunnel.">
            <select v-model="r.transport" class="select w-full">
              <option value="mpath">{{ $t('mpath, spreads over connections') }}</option>
              <option value="kcp">{{ $t('kcp, fast and lossy networks') }}</option>
              <option value="sctp">{{ $t('sctp') }}</option>
              <option value="none">{{ $t('none, raw datagrams (UDP only)') }}</option>
            </select>
          </FormField>
          <FormField label="Encryption" :name="`options.t_routes.${i}.encryption`" hint="Full also encrypts every packet after the handshake.">
            <select v-model="r.encryption" class="select w-full">
              <option value="handshake">{{ $t('handshake only') }}</option>
              <option value="full">{{ $t('full') }}</option>
            </select>
          </FormField>
        </div>
      </Advanced>
    </article>
  </section>
</template>

<script setup lang="ts">
import type { TurnableRoute } from '~/types/api'

const model = defineModel<TurnableRoute[]>({ required: true })
const ctx = inject(formKey, null)
const rootError = computed(() => ctx?.error('options.t_routes') ?? '')

function add() {
  const taken = new Set(model.value.map(r => r.id))
  let n = model.value.length + 1
  while (taken.has(`route-${n}`)) n++
  model.value = [...model.value, { id: `route-${n}`, name: '', target: '', socket: 'udp', transport: 'mpath', encryption: 'handshake' }]
}

function remove(i: number) {
  if (model.value.length > 1) model.value = model.value.filter((_, idx) => idx !== i)
}
</script>

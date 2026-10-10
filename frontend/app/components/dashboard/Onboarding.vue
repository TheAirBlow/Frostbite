<template>
  <section class="surface from-primary/10 to-secondary/10 overflow-hidden bg-gradient-to-br p-5">
    <div class="mb-4 flex items-center justify-between gap-3">
      <div>
        <h2 class="font-display text-xl font-semibold">{{ $t('Let\'s get you set up') }}</h2>
        <p class="text-base-content/60 text-sm">{{ doneCount }} of {{ steps.length }} done. It takes about five minutes.</p>
      </div>
      <progress class="progress progress-primary hidden w-40 sm:block" :value="doneCount" :max="steps.length" />
    </div>
    <ol class="grid gap-2 md:grid-cols-2 xl:grid-cols-5">
      <li v-for="(s, i) in steps" :key="s.title" class="bg-base-100/80 border-base-300 flex flex-col gap-2 rounded-xl border p-3" :class="{ 'opacity-60': s.done }">
        <div class="flex items-center gap-2">
          <span class="grid size-6 shrink-0 place-items-center rounded-full text-xs font-semibold" :class="s.done ? 'bg-success text-success-content' : 'bg-base-300'">
            <Icon v-if="s.done" name="fa6-solid:check" size="11" />
            <template v-else>{{ i + 1 }}</template>
          </span>
          <p class="text-sm font-medium">{{ s.title }}</p>
        </div>
        <p class="text-base-content/60 text-xs">{{ s.text }}</p>
        <button v-if="!s.done" class="btn btn-primary btn-xs mt-auto self-start" @click="s.action()">{{ s.cta }}</button>
      </li>
    </ol>
  </section>
</template>

<script setup lang="ts">
const props = defineProps<{ steps: { done: boolean, title: string, text: string, action: () => void, cta: string }[] }>()
const doneCount = computed(() => props.steps.filter(s => s.done).length)
</script>

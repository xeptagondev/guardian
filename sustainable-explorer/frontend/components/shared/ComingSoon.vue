<script setup lang="ts">
defineProps<{
    message?: string;
    height?: string;
}>();
</script>

<template>
    <div
        class="flex items-center justify-center rounded-xl border bg-card"
        :style="{ height: height ?? '220px' }"
    >
        <p class="text-sm text-muted-foreground">{{ message ?? 'Coming soon' }}</p>
    </div>
</template>

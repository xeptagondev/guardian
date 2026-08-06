<script setup lang="ts">
import { TrendingUp } from 'lucide-vue-next';
import type { ProjectedIssuance } from '~/types/models';
import { formatNumber, truncateText } from '~/lib/format';

const props = defineProps<{
    data: ProjectedIssuance | null | undefined;
}>();

const { t } = useI18n();

const BASELINE_TRUNCATE_LENGTH = 220;
const baselineExpanded = ref(false);
const isBaselineTruncatable = computed(() =>
    (props.data?.baselineDescription?.length ?? 0) > BASELINE_TRUNCATE_LENGTH,
);
const baselineDisplay = computed(() => baselineExpanded.value
    ? (props.data?.baselineDescription ?? '')
    : truncateText(props.data?.baselineDescription, BASELINE_TRUNCATE_LENGTH));

const periodLabel = computed(() => {
    if (!props.data) return '';
    const { periodStart, periodEnd } = props.data;
    if (periodStart == null && periodEnd == null) return t('projects.tbd');
    if (periodStart == null || periodEnd == null || periodStart === periodEnd) {
        return String(periodStart ?? periodEnd);
    }
    return `${periodStart} – ${periodEnd}`;
});

const totalLabel = computed(() => props.data?.totalTco2e != null
    ? `${formatNumber(props.data.totalTco2e)} tCO2e`
    : t('projects.notEstimated'));

</script>

<template>
    <div class="rounded-xl border bg-card overflow-hidden">
        <div class="px-5 py-3.5 border-b bg-muted/30">
            <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
                <TrendingUp class="h-4 w-4 text-primary" />
                {{ $t('projects.projectedIssuance.title') }}
            </h2>
            <p class="text-[11px] text-muted-foreground mt-0.5">{{ $t('projects.projectedIssuance.subtitle') }}</p>
        </div>

        <template v-if="data">
            <div class="px-5 py-4">
                <div class="text-2xl font-bold text-stat-green tabular-nums">
                    {{ totalLabel }}
                </div>
                <div class="text-[11px] text-muted-foreground mt-1">
                    {{ $t('projects.projectedIssuance.totalReductionLabel') }}
                </div>
                <div v-if="data.baselineDescription" class="text-[11px] text-muted-foreground mt-3 pt-3 border-t leading-relaxed">
                    <span class="font-medium text-foreground">{{ $t('projects.projectedIssuance.baselineLabel') }}:</span>
                    {{ baselineDisplay }}
                    <button
                        v-if="isBaselineTruncatable"
                        class="block mt-1 font-medium text-primary hover:underline"
                        @click="baselineExpanded = !baselineExpanded"
                    >
                        {{ baselineExpanded ? $t('common.showLess') : $t('common.showMore') }}
                    </button>
                </div>
            </div>

            <div class="bg-card px-5 py-4 border-t text-center">
                <div class="text-lg font-semibold text-foreground tabular-nums">{{ periodLabel }}</div>
                <div class="text-[11px] text-muted-foreground">{{ $t('projects.projectedIssuance.periodLabel') }}</div>
            </div>
        </template>

        <div v-else class="px-5 py-8 text-center text-sm text-muted-foreground">
            {{ $t('projects.projectedIssuance.emptyTitle') }}
        </div>
    </div>
</template>

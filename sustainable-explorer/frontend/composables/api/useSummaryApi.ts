import type { NetworkId } from '~/composables/useNetwork';

export interface TimelinePointDto {
    period: string;     // "YYYY-MM"
    totalIssued: number;
}

export interface RegistryBreakdownItemDto {
    registry: string;
    totalIssued: number;
}

export interface DashboardSummaryDto {
    totalIssued: number;
    totalRetired: number;
    totalActive: number;
    timeline: TimelinePointDto[];
    registryBreakdown: RegistryBreakdownItemDto[];
}

const emptyDashboardSummary = (): DashboardSummaryDto => ({
    totalIssued: 0,
    totalRetired: 0,
    totalActive: 0,
    timeline: [],
    registryBreakdown: [],
});

export const useDashboardSummaryApi = (opts: { network: Ref<NetworkId | string> }) => {
    const config = useRuntimeConfig();
    const baseURL = import.meta.server
        ? (config.apiBaseUrl as string)
        : (config.public.apiBaseUrl as string);

    const url = computed(() => `/api/v1/${opts.network.value}/dashboard-summary`);
    const key = computed(() => `dashboard-summary:${opts.network.value}`);

    const { data, pending, error, refresh } = useAsyncData<DashboardSummaryDto>(
        key.value,
        async () => {
            try {
                const res = await $fetch<DashboardSummaryDto>(url.value, { baseURL });
                return res ?? emptyDashboardSummary();
            } catch (err) {
                console.error('[useDashboardSummaryApi] fetch failed:', err);
                return emptyDashboardSummary();
            }
        },
        {
            default: () => emptyDashboardSummary(),
            watch: [opts.network],
        },
    );

    return { data, pending, error, refresh };
};

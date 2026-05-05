import type { NetworkId } from '~/composables/useNetwork';

export interface TimelinePointDto {
    period: string;    // "YYYY-MM"
    totalIssued: number;
}

export interface SummaryDto {
    totalIssued: number;
    totalRetired: number;
    totalActive: number;
}

export interface UseSummaryApiOptions {
    network: Ref<NetworkId | string>;
}

const emptySummary = (): SummaryDto => ({
    totalIssued: 0,
    totalRetired: 0,
    totalActive: 0,
});

export const useSummaryApi = (opts: UseSummaryApiOptions) => {
    const config = useRuntimeConfig();
    const baseURL = import.meta.server
        ? (config.apiBaseUrl as string)
        : (config.public.apiBaseUrl as string);

    const url = computed(() => `/api/v1/${opts.network.value}/summary`);
    const key = computed(() => `summary:${opts.network.value}`);

    const { data, pending, error, refresh } = useAsyncData<SummaryDto>(
        key.value,
        async () => {
            try {
                const res = await $fetch<SummaryDto>(url.value, { baseURL });
                return res ?? emptySummary();
            } catch (err) {
                console.error('[useSummaryApi] fetch failed:', err);
                return emptySummary();
            }
        },
        {
            default: () => emptySummary(),
            watch: [opts.network],
        },
    );

    return { data, pending, error, refresh };
};

export const useIssuanceTimelineApi = (opts: { network: Ref<NetworkId | string> }) => {
    const config = useRuntimeConfig();
    const baseURL = import.meta.server
        ? (config.apiBaseUrl as string)
        : (config.public.apiBaseUrl as string);

    const url = computed(() => `/api/v1/${opts.network.value}/summary/timeline`);
    const key = computed(() => `issuance-timeline:${opts.network.value}`);

    const { data, pending, error, refresh } = useAsyncData<TimelinePointDto[]>(
        key.value,
        async () => {
            try {
                return await $fetch<TimelinePointDto[]>(url.value, { baseURL }) ?? [];
            } catch (err) {
                console.error('[useIssuanceTimelineApi] fetch failed:', err);
                return [];
            }
        },
        {
            default: () => [] as TimelinePointDto[],
            watch: [opts.network],
        },
    );

    return { data, pending, error, refresh };
};

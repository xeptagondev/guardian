import type { NetworkId } from '~/composables/useNetwork';
import type { IssuanceListItem } from '~/types/models';

export type IssuanceSortKey = 'mintDate' | 'amount' | 'projectName' | 'tokenId';
export type IssuanceSortDir = 'asc' | 'desc';

export interface IssuancesMeta {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
}

export interface IssuancesResponse {
    data: Record<string, any>[];
    meta: IssuancesMeta;
}

export interface UseIssuancesApiOptions {
    page: Ref<number>;
    limit: Ref<number>;
    search: Ref<string>;
    network: Ref<NetworkId | string>;
    sortBy: Ref<IssuanceSortKey | null>;
    sortDir: Ref<IssuanceSortDir | null>;
    filters: Ref<Record<string, any>>;
}

const ISSUANCE_FILTER_KEYS = ['dateFrom', 'dateTo', 'tokenType', 'projectId'] as const;

const emptyResponse = (limit: number): IssuancesResponse => ({
    data: [],
    meta: { page: 1, limit, total: 0, totalPages: 1 },
});

function mapApiIssuance(raw: Record<string, any>): IssuanceListItem {
    return {
        mintConsensusTimestamp: raw['mintConsensusTimestamp'] ?? '',
        tokenId: raw['tokenId'] ?? null,
        tokenName: raw['tokenName'] ?? null,
        symbol: raw['symbol'] ?? null,
        tokenType: raw['tokenType'] ?? null,
        amount: typeof raw['amount'] === 'number' ? raw['amount'] : 0,
        mintDate: raw['mintDate'] ?? null,
        projectId: raw['projectId'] ?? null,
        projectName: raw['projectName'] ?? null,
        methodology: raw['methodology'] ?? null,
        methodologyId: raw['methodologyId'] ?? null,
        country: raw['country'] ?? null,
        registry: raw['registry'] ?? null,
        linkMethod: raw['linkMethod'] ?? 'unknown',
    };
}

export const useIssuancesApi = (opts: UseIssuancesApiOptions) => {
    const config = useRuntimeConfig();
    const baseURL = import.meta.server
        ? (config.apiBaseUrl as string)
        : (config.public.apiBaseUrl as string);

    const buildQuery = (): Record<string, string | number> => {
        const q: Record<string, string | number> = {
            page: opts.page.value,
            limit: opts.limit.value,
        };
        const search = opts.search.value?.trim();
        if (search) q.search = search;
        if (opts.sortBy.value && opts.sortDir.value) {
            q.sortBy = opts.sortBy.value;
            q.sortDir = opts.sortDir.value;
        }
        const filters = opts.filters.value ?? {};
        for (const key of ISSUANCE_FILTER_KEYS) {
            const raw = filters[key];
            if (raw === null || raw === undefined) continue;
            if (typeof raw === 'string') {
                const trimmed = raw.trim();
                if (trimmed) q[key] = trimmed;
            }
        }
        return q;
    };

    const url = computed(() => `/api/v1/${opts.network.value}/issuances`);

    const key = computed(() => {
        const q = buildQuery();
        return `issuances:${opts.network.value}:${JSON.stringify(q)}`;
    });

    const { data, pending, error, refresh } = useAsyncData<IssuancesResponse>(
        key.value,
        async () => {
            try {
                const res = await $fetch<IssuancesResponse>(url.value, {
                    baseURL,
                    query: buildQuery(),
                });
                return res ?? emptyResponse(opts.limit.value);
            } catch (err) {
                console.error('[useIssuancesApi] fetch failed:', err);
                return emptyResponse(opts.limit.value);
            }
        },
        {
            default: () => emptyResponse(opts.limit.value),
            watch: [
                opts.page,
                opts.limit,
                opts.search,
                opts.network,
                opts.sortBy,
                opts.sortDir,
                opts.filters,
            ],
        },
    );

    const issuances = computed<IssuanceListItem[]>(() =>
        (data.value?.data ?? []).map(mapApiIssuance),
    );

    const meta = computed(() => data.value?.meta ?? emptyResponse(opts.limit.value).meta);

    return { issuances, meta, pending, error, refresh };
};

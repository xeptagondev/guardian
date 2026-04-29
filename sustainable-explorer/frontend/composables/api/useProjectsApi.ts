import type { ProjectsResponse } from '~/types/project';

export type ProjectSortKey = 'name' | 'country' | 'vintage' | 'status' | 'createdAt';

export interface UseProjectsApiOptions {
    network: Ref<string>;
    page: Ref<number>;
    limit: Ref<number>;
    search: Ref<string>;
    country?: Ref<string | null>;
    status?: Ref<string | null>;
    vintage?: Ref<string | null>;
    sector?: Ref<string | null>;
    projectType?: Ref<string | null>;
    sortBy?: Ref<ProjectSortKey | null>;
    sortDir?: Ref<'asc' | 'desc' | null>;
}

const PROJECT_FILTER_KEYS = ['country', 'status', 'vintage', 'sector', 'projectType'] as const;

const empty = (limit: number): ProjectsResponse => ({
    data: [],
    meta: { page: 1, limit, total: 0, totalPages: 1 },
});

export const useProjectsApi = (opts: UseProjectsApiOptions) => {
    const config = useRuntimeConfig();
    const baseURL = import.meta.server
        ? (config.apiBaseUrl as string)
        : (config.public.apiBaseUrl as string);

    const buildQuery = (): Record<string, string | number> => {
        const q: Record<string, string | number> = {
            page: opts.page.value,
            limit: opts.limit.value,
        };
        const s = opts.search.value?.trim();
        if (s) q.search = s;
        for (const key of PROJECT_FILTER_KEYS) {
            const ref = opts[key];
            const v = ref?.value?.trim?.();
            if (v) q[key] = v;
        }
        if (opts.sortBy?.value && opts.sortDir?.value) {
            q.sortBy = opts.sortBy.value;
            q.sortDir = opts.sortDir.value;
        }
        return q;
    };

    const url = computed(() => `/api/v1/${opts.network.value}/projects`);

    const key = computed(() => `projects:${opts.network.value}:${JSON.stringify(buildQuery())}`);

    const watchSources = [
        opts.page, opts.limit, opts.search, opts.network,
        opts.country, opts.status, opts.vintage, opts.sector, opts.projectType,
        opts.sortBy, opts.sortDir,
    ].filter(Boolean) as Ref<unknown>[];

    const { data, pending, error, refresh } = useAsyncData<ProjectsResponse>(
        key.value,
        async () => {
            try {
                const res = await $fetch<ProjectsResponse>(url.value, {
                    baseURL,
                    query: buildQuery(),
                });
                return res ?? empty(opts.limit.value);
            } catch (err) {
                console.error('[useProjectsApi] fetch failed:', err);
                return empty(opts.limit.value);
            }
        },
        {
            default: () => empty(opts.limit.value),
            watch: watchSources,
        },
    );

    return { data, pending, error, refresh };
};

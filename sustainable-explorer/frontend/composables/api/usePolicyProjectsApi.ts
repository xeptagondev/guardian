import type { ProjectsResponse } from '~/types/project';

export interface UsePolicyProjectsApiOptions {
    methodologyId: Ref<string>;
    network: Ref<string>;
    page: Ref<number>;
    limit: Ref<number>;
    search: Ref<string>;
}

export const usePolicyProjectsApi = (opts: UsePolicyProjectsApiOptions) => {
    const config = useRuntimeConfig();
    const baseURL = import.meta.server
        ? (config.apiBaseUrl as string)
        : (config.public.apiBaseUrl as string);

    const url = computed(
        () => `/api/v1/${opts.network.value}/methodologies/${opts.methodologyId.value}/projects`,
    );

    const buildQuery = (): Record<string, string | number> => {
        const q: Record<string, string | number> = {
            page: opts.page.value,
            limit: opts.limit.value,
        };
        const s = opts.search.value?.trim();
        if (s) q.search = s;
        return q;
    };

    const key = computed(
        () => `policy-projects:${opts.network.value}:${opts.methodologyId.value}:${opts.page.value}:${opts.limit.value}:${opts.search.value ?? ''}`,
    );

    const empty = (limit: number): ProjectsResponse => ({
        data: [],
        meta: { page: 1, limit, total: 0, totalPages: 1 },
    });

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
                console.error('[usePolicyProjectsApi] fetch failed:', err);
                return empty(opts.limit.value);
            }
        },
        {
            default: () => empty(opts.limit.value),
            watch: [opts.methodologyId, opts.network, opts.page, opts.limit, opts.search],
        },
    );

    return { data, pending, error, refresh };
};

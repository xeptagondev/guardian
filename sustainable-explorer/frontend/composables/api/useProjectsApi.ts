import type { NetworkId } from '~/composables/useNetwork';
import type { Project } from '~/types/models';
import { mapApiProject } from '~/composables/useProjects';

export type ProjectSortKey =
    | 'name'
    | 'country'
    | 'methodology'
    | 'registry'
    | 'developer'
    | 'vintage'
    | 'status'
    | 'credits'
    | 'issuanceCount'
    | 'createdAt';

export type ProjectSortDir = 'asc' | 'desc';

export interface ProjectsMeta {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
}

export interface ProjectsResponse {
    data: Record<string, any>[];
    meta: ProjectsMeta;
}

export interface UseProjectsApiOptions {
    page: Ref<number>;
    limit: Ref<number>;
    search: Ref<string>;
    network: Ref<NetworkId | string>;
    sortBy: Ref<ProjectSortKey | null>;
    sortDir: Ref<ProjectSortDir | null>;
    filters?: Ref<Record<string, any>>;
}

const PROJECT_FILTER_KEYS = ['name', 'country', 'methodology', 'registry', 'developer', 'vintage', 'status', 'policyTopicId'] as const;

const emptyResponse = (limit: number): ProjectsResponse => ({
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
        const search = opts.search.value?.trim();
        if (search) q.search = search;
        if (opts.sortBy.value && opts.sortDir.value) {
            q.sortBy = opts.sortBy.value;
            q.sortDir = opts.sortDir.value;
        }
        const filters = opts.filters?.value ?? {};
        for (const key of PROJECT_FILTER_KEYS) {
            const raw = filters[key];
            if (raw === null || raw === undefined) continue;
            if (typeof raw === 'string') {
                const trimmed = raw.trim();
                if (trimmed) q[key] = trimmed;
            }
        }
        return q;
    };

    const url = computed(() => `/api/v1/${opts.network.value}/projects`);

    const key = computed(() => {
        const q = buildQuery();
        return `projects:${opts.network.value}:${JSON.stringify(q)}`;
    });

    const { data, pending, error, refresh } = useAsyncData<ProjectsResponse>(
        key.value,
        async () => {
            try {
                const res = await $fetch<ProjectsResponse>(url.value, {
                    baseURL,
                    query: buildQuery(),
                });
                return res ?? emptyResponse(opts.limit.value);
            } catch (err) {
                console.error('[useProjectsApi] fetch failed:', err);
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
                ...(opts.filters ? [opts.filters] : []),
            ],
        },
    );

    const projects = computed<Project[]>(() =>
        (data.value?.data ?? []).map(mapApiProject),
    );

    const meta = computed(() => data.value?.meta ?? emptyResponse(opts.limit.value).meta);

    return { projects, meta, pending, error, refresh };
};

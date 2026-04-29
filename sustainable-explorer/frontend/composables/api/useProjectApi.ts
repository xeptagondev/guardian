import type { ProjectDto } from '~/types/project';

export interface UseProjectApiOptions {
    id: Ref<string>;
    network: Ref<string>;
}

export const useProjectApi = (opts: UseProjectApiOptions) => {
    const config = useRuntimeConfig();
    const baseURL = import.meta.server
        ? (config.apiBaseUrl as string)
        : (config.public.apiBaseUrl as string);

    const url = computed(() => `/api/v1/${opts.network.value}/projects/${opts.id.value}`);
    const key = computed(() => `project:${opts.network.value}:${opts.id.value}`);
    const notFound = ref(false);

    const { data, pending, error, refresh } = useAsyncData<ProjectDto | null>(
        key.value,
        async () => {
            notFound.value = false;
            try {
                return await $fetch<ProjectDto>(url.value, { baseURL });
            } catch (err: any) {
                if (err?.statusCode === 404 || err?.response?.status === 404) {
                    notFound.value = true;
                    return null;
                }
                console.error('[useProjectApi] fetch failed:', err);
                return null;
            }
        },
        {
            default: () => null,
            watch: [opts.id, opts.network],
        },
    );

    return { data, pending, error, refresh, notFound };
};

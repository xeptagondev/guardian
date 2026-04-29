import type { PolicyDetailDto } from '~/types/policy';

export interface UsePolicyDetailApiOptions {
    id: Ref<string>;
    network: Ref<string>;
}

export const usePolicyDetailApi = (opts: UsePolicyDetailApiOptions) => {
    const config = useRuntimeConfig();
    const baseURL = import.meta.server
        ? (config.apiBaseUrl as string)
        : (config.public.apiBaseUrl as string);

    const url = computed(
        () => `/api/v1/${opts.network.value}/methodologies/${opts.id.value}/policy`,
    );
    const key = computed(() => `policy-detail:${opts.network.value}:${opts.id.value}`);
    const notFound = ref(false);

    const { data, pending, error, refresh } = useAsyncData<PolicyDetailDto | null>(
        key.value,
        async () => {
            notFound.value = false;
            try {
                return await $fetch<PolicyDetailDto>(url.value, { baseURL });
            } catch (err: any) {
                if (err?.statusCode === 404 || err?.response?.status === 404) {
                    notFound.value = true;
                    return null;
                }
                console.error('[usePolicyDetailApi] fetch failed:', err);
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

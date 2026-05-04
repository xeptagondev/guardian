import { MOCK_PROJECTS } from '~/data'; // kept aside — not used for live data
import type { Project, ProjectIssuance } from '~/types/models';
import countryAlpha3Data from '~/data/country-alpha3.json';

// country display name → ISO 3166-1 alpha-3 for CountryFlag component
export const COUNTRY_ALPHA3: Record<string, string> = countryAlpha3Data;

function parseSdgs(sdgs: unknown): number[] {
    if (Array.isArray(sdgs)) return (sdgs as unknown[]).map(Number).filter(Boolean);
    if (typeof sdgs === 'string' && sdgs.trim()) {
        return sdgs.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n) && n > 0);
    }
    return [];
}

export function mapApiProject(raw: Record<string, any>): Project {
    const countryCode = COUNTRY_ALPHA3[raw.country] || 'UNK';
    return {
        id: raw.sourceTimestamp || raw.id,
        name: raw.name ?? '',
        country: raw.country ?? '',
        countryCode,
        flag: '',
        lat: raw.lat ?? 0,
        lng: raw.lng ?? 0,
        methodology: raw.methodology ?? '',
        methodologyId: raw.methodologyId ?? '',
        registry: raw.registryName ?? raw.registry ?? raw.registryDid ?? 'Unknown Registry',
        developer: raw.developer ?? '',
        credits: raw.credits ?? 0,
        status: raw.status ?? 'Issuing',
        vintage: raw.vintage ?? '',
        sdgs: parseSdgs(raw.sdgs),
        category: raw.category ?? '',
        sector: raw.sector ?? '',
        sectoralScope: raw.sectoralScope ?? '',
        createdAt: raw.createdAt ?? '',
        creditingPeriodEnd: raw.creditingPeriodEnd ?? null,
        topicId: raw.topicId ?? undefined,
        policyTopicId: raw.policyTopicId ?? undefined,
        registryDid: raw.registryDid ?? undefined,
        sourceTimestamp: raw.sourceTimestamp ?? undefined,
        issuanceCount: typeof raw.issuanceCount === 'number' ? raw.issuanceCount : 0,
        issuances: Array.isArray(raw.issuances)
            ? (raw.issuances as Array<Record<string, any>>).map((i): ProjectIssuance => ({
                tokenId: i['tokenId'] ?? '',
                name: i['name'] ?? null,
                symbol: i['symbol'] ?? null,
                type: i['type'] ?? null,
                supply: typeof i['supply'] === 'number' ? i['supply'] : 0,
                mintDate: i['mintDate'] ?? null,
                rawVc: i['rawVc'] ?? null,
            }))
            : [],
        totalIssued: typeof raw.totalIssued === 'number' ? raw.totalIssued : 0,
        totalRetired: typeof raw.totalRetired === 'number' ? raw.totalRetired : 0,
        totalActive: typeof raw.totalActive === 'number' ? raw.totalActive : 0,
    };
}


export function useMockProjects() {
    return MOCK_PROJECTS;
}

export function useProjectDetail(id: Ref<string>) {
    const { network } = useNetwork();
    const config = useRuntimeConfig();

    const baseURL = import.meta.server
        ? (config.apiBaseUrl as string)
        : (config.public.apiBaseUrl as string);

    const key = computed(() => `project:${network.value}:${id.value}`);
    const url = computed(() => `/api/v1/${network.value}/projects/${id.value}`);

    const { data, pending, error } = useAsyncData<Record<string, any>>(
        key.value,
        () => $fetch(url.value, { baseURL }),
        {
            watch: [network, id],
            default: () => null,
        },
    );

    const project = computed<Project | null>(() => {
        if (!data.value) return null;
        return mapApiProject(data.value);
    });

    return { project, pending, error };
}

export interface ActivityEvent {
    date: string;
    action: string;
    type: string;
}

const VALID_ACTIVITY_TYPES = new Set(['document', 'verification', 'registry', 'monitoring', 'credit']);

function mapActivityEvent(raw: Record<string, unknown>): ActivityEvent {
    const type = typeof raw.type === 'string' && VALID_ACTIVITY_TYPES.has(raw.type)
        ? raw.type
        : 'document';
    return {
        date: typeof raw.date === 'string' ? raw.date : '',
        action: typeof raw.action === 'string' ? raw.action : 'Activity recorded',
        type,
    };
}

export function useProjectActivity(id: Ref<string>) {
    const { network } = useNetwork();
    const config = useRuntimeConfig();

    const baseURL = import.meta.server
        ? (config.apiBaseUrl as string)
        : (config.public.apiBaseUrl as string);

    const key = computed(() => `project-activity:${network.value}:${id.value}`);
    const url = computed(() => `/api/v1/${network.value}/projects/${id.value}/activity`);

    const { data, pending, error } = useAsyncData<ActivityEvent[]>(
        key.value,
        async () => {
            try {
                const raw = await $fetch<Record<string, unknown>[]>(url.value, { baseURL });
                return Array.isArray(raw) ? raw.map(mapActivityEvent) : [];
            } catch {
                return [];
            }
        },
        {
            watch: [network, id],
            default: () => [],
        },
    );

    return { activity: data, pending, error };
}

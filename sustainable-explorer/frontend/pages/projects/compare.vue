<script setup lang="ts">
import { ArrowLeft, X } from 'lucide-vue-next';
import { formatCredits } from '~/lib/format';
import { mapApiProject } from '~/composables/useProjects';
import type { Project } from '~/types/models';

const route = useRoute();
const { network } = useNetwork();
const { toggleProject } = useProjectComparison();

// Parse the comma-separated ids from the query string
const ids = computed<string[]>(() => {
    const raw = route.query.ids as string | undefined;
    if (!raw) return [];
    return raw.split(',').map(s => s.trim()).filter(Boolean);
});

// Fetch all projects in one useAsyncData call using Promise.all
const config = useRuntimeConfig();
const baseURL = import.meta.server
    ? (config.apiBaseUrl as string)
    : (config.public.apiBaseUrl as string);

const { data: rawProjects, pending } = useAsyncData<Record<string, any>[]>(
    () => `compare-${ids.value.join(',')}-${network.value}`,
    async () => {
        if (ids.value.length === 0) return [];
        return Promise.all(
            ids.value.map(id =>
                $fetch<Record<string, any>>(`/api/v1/${network.value}/projects/${id}`, { baseURL }).catch(() => null),
            ),
        );
    },
    { watch: [network, ids] },
);

const projects = computed<(Project | null)[]>(() => {
    if (!rawProjects.value) return ids.value.map(() => null);
    return (rawProjects.value as (Record<string, any> | null)[]).map(r =>
        r ? mapApiProject(r) : null,
    );
});

// Remove a project from comparison (navigates with updated ids)
const router = useRouter();
function removeProject(id: string) {
    toggleProject(id, '');
    const remaining = ids.value.filter(i => i !== id);
    if (remaining.length === 0) {
        router.push('/projects');
    } else {
        router.replace({ query: { ids: remaining.join(',') } });
    }
}

// Status badge colours — same map as index.vue
const statusColor: Record<string, string> = {
    Registered: 'bg-slate-100 text-slate-600',
    'Under Validation': 'bg-stat-amber/10 text-stat-amber',
    Verified: 'bg-stat-blue/10 text-stat-blue',
    Issuing: 'bg-stat-green/10 text-stat-green',
    Completed: 'bg-purple-50 text-purple-600',
};

// Rows definition
interface CompareRow {
    label: string;
    key: keyof Project | 'creditsFormatted' | 'totalIssuedFormatted' | 'totalRetiredFormatted' | 'totalActiveFormatted';
    render: 'text' | 'status' | 'country' | 'sdgs' | 'credits';
}

const rows: CompareRow[] = [
    { label: 'Status', key: 'status', render: 'status' },
    { label: 'Country', key: 'country', render: 'country' },
    { label: 'Registry', key: 'registry', render: 'text' },
    { label: 'Methodology', key: 'methodology', render: 'text' },
    { label: 'Sector', key: 'sector', render: 'text' },
    { label: 'Vintage', key: 'vintage', render: 'text' },
    { label: 'Credits (ER_y)', key: 'credits', render: 'credits' },
    { label: 'Total Issued', key: 'totalIssued', render: 'credits' },
    { label: 'Total Retired', key: 'totalRetired', render: 'credits' },
    { label: 'Total Active', key: 'totalActive', render: 'credits' },
    { label: 'Issuances', key: 'issuanceCount', render: 'text' },
    { label: 'Crediting Period End', key: 'creditingPeriodEnd', render: 'text' },
    { label: 'SDGs', key: 'sdgs', render: 'sdgs' },
    { label: 'Developer', key: 'developer', render: 'text' },
];

// Return the raw string/number value for a project + key, for diff detection
function rawValue(project: Project | null, key: string): string {
    if (!project) return '';
    const val = (project as Record<string, any>)[key];
    if (Array.isArray(val)) return val.join(',');
    return String(val ?? '');
}

// Detect whether values differ across all non-null projects for a given key
function hasDiff(key: string): boolean {
    const loaded = projects.value.filter(p => p !== null) as Project[];
    if (loaded.length < 2) return false;
    const first = rawValue(loaded[0], key);
    return loaded.some(p => rawValue(p, key) !== first);
}

// Get display text value
function cellText(project: Project | null, key: keyof Project | string): string {
    if (!project) return '—';
    const val = (project as Record<string, any>)[key];
    if (val === null || val === undefined || val === '') return '—';
    if (key === 'credits' || key === 'totalIssued' || key === 'totalRetired' || key === 'totalActive') {
        return formatCredits(Number(val) || 0);
    }
    return String(val);
}
</script>

<template>
    <div class="space-y-0">
        <!-- Page Header -->
        <div class="px-6 pt-6 pb-4 flex items-center gap-3">
            <NuxtLink
                to="/projects"
                class="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
                <ArrowLeft class="h-4 w-4" />
                Back to Projects
            </NuxtLink>
        </div>

        <div class="px-6 pb-2">
            <h1 class="text-2xl font-bold text-foreground">Compare Projects</h1>
            <p class="text-sm text-muted-foreground mt-1">Side-by-side comparison of selected projects</p>
        </div>

        <!-- Empty / too-few guard -->
        <div v-if="ids.length < 2" class="px-6 py-16 text-center">
            <p class="text-sm text-muted-foreground">Select at least 2 projects to compare.</p>
            <NuxtLink
                to="/projects"
                class="mt-4 inline-flex items-center gap-1.5 text-sm text-primary hover:underline font-medium"
            >
                <ArrowLeft class="h-4 w-4" />
                Go to Projects
            </NuxtLink>
        </div>

        <div v-else class="px-6 pb-8">
            <div class="rounded-xl border bg-card overflow-x-auto">
                <table class="w-full text-sm">
                    <!-- Sticky project header row -->
                    <thead class="sticky top-0 z-10 bg-card shadow-[0_1px_0_0_hsl(var(--border))]">
                        <tr>
                            <!-- Label column header -->
                            <th class="min-w-[160px] w-44 py-3 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider border-r bg-muted/30" />
                            <!-- One column per project -->
                            <th
                                v-for="(project, idx) in projects"
                                :key="ids[idx]"
                                class="py-3 px-4 text-left align-top border-r last:border-r-0"
                                :class="pending ? 'min-w-[200px]' : 'min-w-[220px]'"
                            >
                                <div v-if="pending" class="space-y-1.5 animate-pulse">
                                    <div class="h-4 w-3/4 rounded bg-muted" />
                                    <div class="h-3 w-1/2 rounded bg-muted" />
                                </div>
                                <div v-else-if="project" class="flex items-start justify-between gap-2">
                                    <NuxtLink
                                        :to="`/projects/${project.id}`"
                                        class="font-semibold text-foreground hover:text-primary transition-colors leading-snug"
                                    >
                                        {{ project.name }}
                                    </NuxtLink>
                                    <button
                                        class="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                                        title="Remove from comparison"
                                        @click="removeProject(ids[idx])"
                                    >
                                        <X class="h-3.5 w-3.5" />
                                    </button>
                                </div>
                                <div v-else class="text-xs text-muted-foreground italic">
                                    Project not found
                                </div>
                            </th>
                        </tr>
                    </thead>

                    <tbody class="divide-y">
                        <tr
                            v-for="row in rows"
                            :key="row.key"
                            class="group"
                        >
                            <!-- Row label -->
                            <td class="py-3 px-4 font-medium text-sm text-muted-foreground border-r bg-muted/20 align-middle whitespace-nowrap">
                                {{ row.label }}
                            </td>

                            <!-- One cell per project -->
                            <td
                                v-for="(project, idx) in projects"
                                :key="ids[idx]"
                                class="py-3 px-4 border-r last:border-r-0 align-middle transition-colors"
                                :class="hasDiff(row.key) ? 'bg-amber-50' : ''"
                            >
                                <!-- Loading placeholder -->
                                <div v-if="pending" class="animate-pulse">
                                    <div class="h-4 w-24 rounded bg-muted" />
                                </div>

                                <!-- Status badge -->
                                <template v-else-if="row.render === 'status'">
                                    <span
                                        v-if="project"
                                        :class="[statusColor[project.status] || 'bg-muted text-muted-foreground', 'text-xs font-medium rounded-full px-2 py-0.5']"
                                    >
                                        {{ project.status }}
                                    </span>
                                    <span v-else class="text-muted-foreground">—</span>
                                </template>

                                <!-- Country with flag -->
                                <template v-else-if="row.render === 'country'">
                                    <div v-if="project && project.country" class="flex items-center gap-1.5">
                                        <CountryFlag :code="project.countryCode" size="sm" />
                                        <span class="text-sm text-foreground">{{ project.country }}</span>
                                    </div>
                                    <span v-else class="text-muted-foreground">—</span>
                                </template>

                                <!-- SDG badges -->
                                <template v-else-if="row.render === 'sdgs'">
                                    <div v-if="project && project.sdgs?.length">
                                        <SdgBadges :ids="project.sdgs" :max="6" />
                                    </div>
                                    <span v-else class="text-muted-foreground">—</span>
                                </template>

                                <!-- Credits (formatted number) -->
                                <template v-else-if="row.render === 'credits'">
                                    <span class="tabular-nums font-medium text-foreground">
                                        {{ project ? formatCredits(Number((project as any)[row.key]) || 0) : '—' }}
                                    </span>
                                </template>

                                <!-- Plain text fallback -->
                                <template v-else>
                                    <span class="text-foreground">{{ cellText(project, row.key) }}</span>
                                </template>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Diff legend -->
            <p class="mt-2 text-[11px] text-muted-foreground">
                <span class="inline-block h-3 w-3 rounded-sm bg-amber-100 border border-amber-200 mr-1 align-middle" />
                Highlighted rows indicate values that differ between projects.
            </p>
        </div>
    </div>
</template>

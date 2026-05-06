<script setup lang="ts">
import { FileJson, Sparkles, X, ArrowRight } from 'lucide-vue-next';
import type { FilterOption } from '~/components/shared/FilterBar.vue';
import type { ProjectSortKey, ProjectSortDir } from '~/composables/api/useProjectsApi';
import { formatCredits } from '~/lib/format';
import { SDG_LIST } from '~/lib/sdgs';
import { SECTORS } from '~/lib/enums';
import { generateProjectVc } from '~/lib/mock-vc';
import { MOCK_TRANSFERS, MOCK_RETIREMENTS } from '~/data';
import { getMethodologyLongName } from '~/lib/methodologies';
import type { Project } from '~/types/models';

const { selectedIds, selectedEntries, canAdd, isSelected, toggleProject, clearAll } = useProjectComparison();

const { t } = useI18n();
const { network } = useNetwork();
const route = useRoute();
const router = useRouter();

const pageSize = ref(route.query.limit ? parseInt(route.query.limit as string) : 10);

// Server-side pagination state — initialised from URL query params
const currentPage = ref(route.query.page ? parseInt(route.query.page as string) : 1);
const searchQuery = ref((route.query.q as string) || '');
const sortKey = ref<ProjectSortKey | null>((route.query.sort as ProjectSortKey) || 'createdAt');
const sortDir = ref<ProjectSortDir | null>((route.query.dir as ProjectSortDir) || 'desc');

const RESERVED = new Set(['q', 'page', 'sort', 'dir']);
const initialFilters: Record<string, string> = {};
for (const [k, v] of Object.entries(route.query)) {
    if (!RESERVED.has(k) && typeof v === 'string' && v) initialFilters[k] = v;
}
const activeFilters = ref<Record<string, string>>(initialFilters);

function syncUrl() {
    const query: Record<string, string> = {};
    if (searchQuery.value) query.q = searchQuery.value;
    if (currentPage.value > 1) query.page = String(currentPage.value);
    if (sortKey.value && sortDir.value && !(sortKey.value === 'createdAt' && sortDir.value === 'desc')) {
        query.sort = sortKey.value;
        query.dir = sortDir.value;
    }
    for (const [k, v] of Object.entries(activeFilters.value)) {
        if (v) query[k] = v;
    }
    router.replace({ query });
}

function toggleSort(key: ProjectSortKey) {
    if (sortKey.value === key) {
        if (sortDir.value === 'asc') sortDir.value = 'desc';
        else if (sortDir.value === 'desc') { sortKey.value = null; sortDir.value = null; }
        else sortDir.value = 'asc';
    } else {
        sortKey.value = key;
        sortDir.value = 'asc';
    }
    currentPage.value = 1;
    syncUrl();
}

function setFilter(key: string, value: string) {
    activeFilters.value = { ...activeFilters.value, [key]: value };
    currentPage.value = 1;
    syncUrl();
}

function clearFilters() {
    activeFilters.value = {};
    searchQuery.value = '';
    currentPage.value = 1;
    syncUrl();
}

function applyPreset(preset: { search?: string; filters?: Record<string, string> }) {
    searchQuery.value = preset.search || '';
    activeFilters.value = preset.filters ? { ...preset.filters } : {};
    currentPage.value = 1;
    syncUrl();
}

watch(searchQuery, () => { currentPage.value = 1; syncUrl(); });
watch(currentPage, syncUrl);

const { projects, meta, pending } = useProjectsApi({
    page: currentPage,
    limit: pageSize,
    search: searchQuery,
    network,
    sortBy: sortKey,
    sortDir,
    filters: activeFilters,
});

const { resolvedCode } = useGeocodedCountries(projects);

function displayCountry(p: Project): string | null {
    return p.countryCode !== 'UNK' ? p.country : null;
}

// Aggregate transferred/retired per project
const transferredByProject = computed(() => {
    const map: Record<string, number> = {};
    for (const t of MOCK_TRANSFERS) { map[t.projectId] = (map[t.projectId] || 0) + t.quantity; }
    return map;
});
const retiredByProject = computed(() => {
    const map: Record<string, number> = {};
    for (const r of MOCK_RETIREMENTS) { map[r.projectId] = (map[r.projectId] || 0) + r.quantity; }
    return map;
});

const vcViewerOpen = ref(false);
const vcViewerTitle = ref('');
const vcViewerData = ref<Record<string, any> | null>(null);

function viewVc(p: Project) {
    vcViewerTitle.value = p.name;
    vcViewerData.value = generateProjectVc(p);
    vcViewerOpen.value = true;
}

const displayProjects = computed(() => projects.value.map(p => ({
    ...p,
    creditsFormatted: formatCredits(p.credits),
    transferred: transferredByProject.value[p.id] || 0,
    transferredFormatted: formatCredits(transferredByProject.value[p.id] || 0),
    retired: retiredByProject.value[p.id] || 0,
    retiredFormatted: formatCredits(retiredByProject.value[p.id] || 0),
    methodologyLong: getMethodologyLongName(p.methodologyId, p.methodology),
})));

const presets = computed(() => [
    { label: t('projects.presets.issuingForestry'), filters: { status: 'Issuing', sector: 'Land Use & Forestry' } },
    { label: t('projects.presets.goldStandard'), filters: { registry: 'Gold Standard' } },
    { label: t('projects.presets.sdg13'), filters: { sdgs: '13' } },
    { label: t('projects.presets.underValidation'), filters: { status: 'Under Validation' } },
    { label: t('projects.presets.vintage2024'), filters: { vintage: '2024' } },
    { label: t('projects.presets.blueCarbon'), search: 'Blue Carbon' },
]);

// Static filter options — status and sector are known system-level values.
// Registry and vintage are passed as text via the search box.
const filters = computed<FilterOption[]>(() => [
    {
        key: 'status',
        label: t('projects.filters.status'),
        options: ['Issuing', 'Under Validation', 'Registered', 'Verified', 'Completed'].map(s => ({ value: s, label: s })),
    },
    {
        key: 'sector',
        label: t('projects.filters.sector'),
        options: SECTORS.map(s => ({ value: s, label: s })),
    },
    {
        key: 'sdgs',
        label: t('projects.filters.sdgs'),
        multiSelect: true,
        options: SDG_LIST.map(s => ({
            value: String(s.id),
            label: `SDG ${s.id}: ${s.name}`,
            icon: `/sdgs/E-WEB-Goal-${String(s.id).padStart(2, '0')}.png`,
        })),
    },
]);

const statusColor: Record<string, string> = {
    Registered: 'bg-slate-100 text-slate-600',
    'Under Validation': 'bg-stat-amber/10 text-stat-amber',
    Verified: 'bg-stat-blue/10 text-stat-blue',
    Issuing: 'bg-stat-green/10 text-stat-green',
    Completed: 'bg-purple-50 text-purple-600',
};
</script>

<template>
    <div class="space-y-0">
        <div class="px-6 pt-6 pb-4">
            <h1 class="text-2xl font-bold text-foreground">{{ $t('projects.title') }}</h1>
            <p class="text-sm text-muted-foreground mt-1">{{ $t('projects.subtitle') }}</p>
        </div>

        <div class="px-6 pb-3">
            <FilterBar
                v-model="searchQuery"
                :filters="filters"
                :active-filters="activeFilters"
                :result-count="meta.total"
                :total-count="meta.total"
                :search-placeholder="$t('projects.searchPlaceholder')"
                @filter="setFilter"
                @clear="clearFilters"
            />

            <!-- Preset Templates -->
            <div class="flex items-center gap-2 mt-2.5 flex-wrap">
                <span class="flex items-center gap-1 text-[11px] text-muted-foreground">
                    <Sparkles class="h-3 w-3" /> {{ $t('projects.quickFilters') }}
                </span>
                <button
                    v-for="preset in presets"
                    :key="preset.label"
                    class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-medium text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                    @click="applyPreset({ search: preset.search, filters: preset.filters } as any)"
                >
                    {{ preset.label }}
                </button>
            </div>
        </div>

        <div class="px-6 pb-6">
            <div class="rounded-xl border bg-card overflow-x-auto">
                <table class="w-full text-sm min-w-[900px]">
                    <thead>
                        <tr class="border-b bg-muted/30">
                            <th class="w-10 py-2.5 px-3 text-xs font-medium text-muted-foreground uppercase tracking-wider" />
                            <SortableHeader :label="$t('projects.columns.project')" sort-key="name" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader :label="$t('projects.columns.country')" sort-key="country" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader :label="$t('projects.columns.registry')" sort-key="registry" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader :label="$t('projects.columns.methodology')" sort-key="methodology" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader :label="$t('projects.columns.sector')" sort-key="sector" :tooltip="$t('projects.sectorTooltip')" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader :label="$t('projects.columns.issuances')" sort-key="issuanceCount" align="right" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader :label="$t('projects.columns.transferred')" sort-key="transferred" align="right" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader :label="$t('projects.columns.retired')" sort-key="retired" align="right" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader :label="$t('projects.columns.status')" sort-key="status" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <th class="text-left py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider min-w-[160px]">
                                <span class="inline-flex items-center gap-1">
                                    {{ $t('projects.columns.sdgs') }}
                                    <InfoTooltip :text="$t('projects.sdgsTooltip')" />
                                </span>
                            </th>
                            <th class="text-center py-2.5 px-3 text-xs font-medium text-muted-foreground uppercase tracking-wider"><span class="inline-flex items-center gap-1">{{ $t('projects.columns.rawData') }} <InfoTooltip :text="$t('tooltips.viewRawData')" /></span></th>
                        </tr>
                    </thead>
                    <tbody class="divide-y">
                        <tr v-if="pending" v-for="i in pageSize" :key="`skel-${i}`" class="animate-pulse">
                            <td class="py-3 px-3"><div class="mx-auto h-4 w-4 rounded bg-muted" /></td>
                            <td class="py-3 px-4"><div class="h-4 w-40 rounded bg-muted" /></td>
                            <td class="py-3 px-4"><div class="h-4 w-20 rounded bg-muted" /></td>
                            <td class="py-3 px-4"><div class="h-4 w-24 rounded bg-muted" /></td>
                            <td class="py-3 px-4"><div class="h-5 w-16 rounded bg-muted" /></td>
                            <td class="py-3 px-4"><div class="h-4 w-24 rounded bg-muted" /></td>
                            <td class="py-3 px-4"><div class="h-4 w-10 rounded bg-muted ml-auto" /></td>
                            <td class="py-3 px-4"><div class="h-4 w-12 rounded bg-muted ml-auto" /></td>
                            <td class="py-3 px-4"><div class="h-4 w-12 rounded bg-muted ml-auto" /></td>
                            <td class="py-3 px-4"><div class="h-5 w-16 rounded-full bg-muted" /></td>
                            <td class="py-3 px-4"><div class="h-5 w-24 rounded bg-muted" /></td>
                            <td class="py-3 px-3"><div class="mx-auto h-7 w-7 rounded-md bg-muted" /></td>
                        </tr>
                        <tr
                            v-else
                            v-for="p in displayProjects"
                            :key="p.id"
                            class="hover:bg-muted/30 transition-colors cursor-pointer"
                        >
                            <td class="py-3 px-3 text-center" @click.stop>
                                <input
                                    type="checkbox"
                                    :checked="isSelected(p.id)"
                                    :disabled="!canAdd && !isSelected(p.id)"
                                    :class="[
                                        'h-4 w-4 rounded border-border cursor-pointer accent-primary',
                                        !canAdd && !isSelected(p.id) ? 'opacity-30 cursor-not-allowed' : '',
                                    ]"
                                    @change="toggleProject(p.id, p.name)"
                                />
                            </td>
                            <td class="py-3 px-4">
                                <NuxtLink :to="`/projects/${p.id}`" class="font-medium text-foreground hover:text-primary transition-colors">{{ p.name }}</NuxtLink>
                            </td>
                            <td class="py-3 px-4 text-muted-foreground">
                                <div class="group relative inline-flex items-center gap-1.5">
                                    <CountryFlag :code="resolvedCode(p)" size="sm" />
                                    <span class="hidden md:inline">{{ displayCountry(p) }}</span>
                                    <div v-if="displayCountry(p)" class="md:hidden pointer-events-none absolute bottom-full left-1/2 -translate-x-1/2 mb-2 opacity-0 group-hover:opacity-100 transition-opacity z-[100]">
                                        <div class="whitespace-nowrap rounded-md bg-foreground px-2.5 py-1 text-[11px] text-background shadow-lg">
                                            {{ displayCountry(p) }}
                                        </div>
                                        <div class="mx-auto h-0 w-0 border-x-[5px] border-x-transparent border-t-[5px] border-t-foreground" />
                                    </div>
                                </div>
                            </td>
                            <td class="py-3 px-4 text-muted-foreground text-xs">{{ p.registry }}</td>
                            <td class="py-3 px-4">
                                <div class="group relative inline-block">
                                    <span class="text-xs bg-muted rounded px-1.5 py-0.5 cursor-default">{{ p.methodology }}</span>
                                    <div class="pointer-events-none absolute bottom-full left-0 mb-2 opacity-0 group-hover:opacity-100 transition-opacity z-[100] w-80">
                                        <div class="whitespace-normal rounded-md bg-foreground px-2.5 py-1.5 text-[11px] text-background shadow-lg leading-snug">
                                            {{ p.methodologyLong }}
                                        </div>
                                        <div class="ml-3 h-0 w-0 border-x-[5px] border-x-transparent border-t-[5px] border-t-foreground" />
                                    </div>
                                </div>
                            </td>
                            <td class="py-3 px-4">
                                <div class="group relative inline-block">
                                    <span class="text-xs text-muted-foreground cursor-default">{{ p.sector }}</span>
                                    <div class="pointer-events-none absolute bottom-full left-0 mb-2 opacity-0 group-hover:opacity-100 transition-opacity z-[100] max-w-xs">
                                        <div class="whitespace-normal rounded-md bg-foreground px-2.5 py-1.5 text-[11px] text-background shadow-lg leading-snug">
                                            {{ $t('projects.sectoralScope', { scope: p.sectoralScope }) }}
                                        </div>
                                        <div class="ml-3 h-0 w-0 border-x-[5px] border-x-transparent border-t-[5px] border-t-foreground" />
                                    </div>
                                </div>
                            </td>
                            <td class="py-3 px-4 text-right tabular-nums font-medium">{{ p.issuanceCount ?? 0 }}</td>
                            <td class="py-3 px-4 text-right tabular-nums text-muted-foreground">{{ p.transferredFormatted }}</td>
                            <td class="py-3 px-4 text-right tabular-nums text-muted-foreground">{{ p.retiredFormatted }}</td>
                            <td class="py-3 px-4">
                                <span :class="[statusColor[p.status] || 'bg-muted text-muted-foreground', 'text-xs font-medium rounded-full px-2 py-0.5']">
                                    {{ p.status }}
                                </span>
                            </td>
                            <td class="py-3 px-4">
                                <SdgBadges :ids="p.sdgs" :max="4" />
                            </td>
                            <td class="py-3 px-3 text-center">
                                <button
                                    class="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                                    :title="$t('common.viewRawData')"
                                    @click.stop="viewVc(p)"
                                >
                                    <FileJson class="h-3.5 w-3.5" />
                                </button>
                            </td>
                        </tr>
                        <tr v-if="!pending && displayProjects.length === 0">
                            <td colspan="12" class="py-12 text-center text-sm text-muted-foreground">{{ $t('projects.noMatch') }}</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Comparison Bar -->
            <Transition
                enter-active-class="transition-all duration-200 ease-out"
                enter-from-class="opacity-0 translate-y-2"
                enter-to-class="opacity-100 translate-y-0"
                leave-active-class="transition-all duration-150 ease-in"
                leave-from-class="opacity-100 translate-y-0"
                leave-to-class="opacity-0 translate-y-2"
            >
                <div
                    v-if="selectedIds.length > 0"
                    class="sticky bottom-0 z-20 mt-3 flex items-center gap-3 rounded-xl border bg-card px-4 py-3 shadow-md"
                >
                    <span class="text-xs font-medium text-muted-foreground shrink-0">Compare:</span>
                    <div class="flex flex-1 flex-wrap items-center gap-2">
                        <span
                            v-for="entry in selectedEntries"
                            :key="entry.id"
                            class="inline-flex items-center gap-1.5 rounded-full border bg-primary/8 px-2.5 py-0.5 text-xs font-medium text-foreground"
                        >
                            {{ entry.name }}
                            <button
                                class="ml-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-full text-muted-foreground hover:text-foreground transition-colors"
                                @click="toggleProject(entry.id, entry.name)"
                            >
                                <X class="h-3 w-3" />
                            </button>
                        </span>
                    </div>
                    <div class="flex items-center gap-2 shrink-0">
                        <button
                            class="inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                            @click="clearAll()"
                        >
                            <X class="h-3.5 w-3.5" />
                            Clear
                        </button>
                        <NuxtLink
                            :to="`/projects/compare?ids=${selectedIds.join(',')}`"
                            class="inline-flex items-center gap-1.5 rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
                        >
                            Compare
                            <ArrowRight class="h-3.5 w-3.5" />
                        </NuxtLink>
                    </div>
                </div>
            </Transition>

            <Pagination
                v-model:current-page="currentPage"
                v-model:page-size="pageSize"
                :total-pages="meta.totalPages"
                :total-items="meta.total"
            />
        </div>

        <VcJsonViewer :open="vcViewerOpen" :title="vcViewerTitle" :data="vcViewerData" @close="vcViewerOpen = false" />
    </div>
</template>

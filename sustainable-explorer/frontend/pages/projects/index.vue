<script setup lang="ts">
import { FolderKanban, FileJson, Sparkles } from 'lucide-vue-next';
import type { FilterOption } from '~/components/shared/FilterBar.vue';
import { formatCredits } from '~/lib/format';
import { SDG_LIST } from '~/lib/sdgs';
import { generateProjectVc } from '~/lib/mock-vc';
import type { Project } from '~/types/models';

const { projects, total, filterOptions } = useProjects();

const vcViewerOpen = ref(false);
const vcViewerTitle = ref('');
const vcViewerData = ref<Record<string, any> | null>(null);

function viewVc(p: Project) {
    vcViewerTitle.value = p.name;
    vcViewerData.value = generateProjectVc(p);
    vcViewerOpen.value = true;
}

const allProjects = computed(() => projects.value.map(p => ({
    ...p,
    creditsFormatted: formatCredits(p.credits),
})));

const { searchQuery, currentPage, paginated, filtered, totalPages, pageSize, activeFilters, sortKey, sortDir, toggleSort, setFilter, clearFilters, applyPreset } =
    useFilteredPagination(allProjects, {
        searchFields: ['name', 'country', 'methodology', 'registry', 'sector', 'sectoralScope'],
        pageSize: 8,
        defaultSort: { key: 'credits', dir: 'desc' },
        arrayFields: ['sdgs'],
    });

const presets = [
    { label: 'Active Forestry', filters: { status: 'Active', sector: 'Forestry and Land Use' } },
    { label: 'Gold Standard', filters: { registry: 'Gold Standard' } },
    { label: 'SDG 13: Climate Action', filters: { sdgs: '13' } },
    { label: 'Verification Pending', filters: { status: 'Verification' } },
    { label: 'Vintage 2024', filters: { vintage: '2024' } },
    { label: 'Blue Carbon', search: 'Blue Carbon' },
];

// Summary statistics for filtered results
const summaryStats = computed(() => {
    const f = filtered.value;
    const totalIssuances = f.reduce((sum, p) => sum + p.credits, 0);
    const uniqueCountries = new Set(f.map(p => p.country)).size;
    const uniqueRegistries = new Set(f.map(p => p.registry)).size;
    return { totalIssuances, uniqueCountries, uniqueRegistries };
});

const filters = computed<FilterOption[]>(() => [
    {
        key: 'status',
        label: 'Status',
        options: filterOptions.value.statuses.map(s => ({ value: s, label: s })),
    },
    {
        key: 'registry',
        label: 'Registry',
        options: filterOptions.value.registries.map(r => ({ value: r, label: r })),
    },
    {
        key: 'vintage',
        label: 'Vintage',
        options: filterOptions.value.vintages.map(v => ({ value: v, label: v })),
    },
    {
        key: 'sector',
        label: 'Sector',
        options: filterOptions.value.sectors.map(s => ({ value: s, label: s })),
    },
    {
        key: 'sectoralScope',
        label: 'Sectoral Scope',
        options: filterOptions.value.sectoralScopes.map(s => ({ value: s, label: s })),
    },
    {
        key: 'sdgs',
        label: 'SDGs',
        multiSelect: true,
        options: SDG_LIST.map(s => ({
            value: String(s.id),
            label: `SDG ${s.id}: ${s.name}`,
            icon: `/sdgs/E-WEB-Goal-${String(s.id).padStart(2, '0')}.png`,
        })),
    },
]);

const statusColor: Record<string, string> = {
    Active: 'bg-stat-green/10 text-stat-green',
    Verification: 'bg-stat-amber/10 text-stat-amber',
    Monitoring: 'bg-stat-blue/10 text-stat-blue',
};
</script>

<template>
    <div class="space-y-0">
        <div class="px-6 pt-6 pb-4">
            <h1 class="text-2xl font-bold text-foreground">Projects</h1>
            <p class="text-sm text-muted-foreground mt-1">Verified sustainability projects on the Guardian network</p>
        </div>

        <div class="px-6 pb-3">
            <FilterBar
                v-model="searchQuery"
                :filters="filters"
                :active-filters="activeFilters"
                :result-count="filtered.length"
                :total-count="total"
                search-placeholder="Search projects..."
                @filter="setFilter"
                @clear="clearFilters"
            />

            <!-- Preset Templates -->
            <div class="flex items-center gap-2 mt-2.5 flex-wrap">
                <span class="flex items-center gap-1 text-[11px] text-muted-foreground">
                    <Sparkles class="h-3 w-3" /> Quick filters:
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

        <!-- Summary Stats -->
        <div v-if="filtered.length !== total" class="px-6 pb-3">
            <div class="flex items-center gap-4 rounded-lg bg-muted/50 px-4 py-2.5 text-xs">
                <span class="font-medium text-foreground">{{ filtered.length }} projects found</span>
                <span class="text-muted-foreground">&middot;</span>
                <span class="text-muted-foreground">Total issuances: <strong class="text-foreground">{{ formatCredits(summaryStats.totalIssuances) }}</strong></span>
                <span class="text-muted-foreground">&middot;</span>
                <span class="text-muted-foreground">Countries: <strong class="text-foreground">{{ summaryStats.uniqueCountries }}</strong></span>
                <span class="text-muted-foreground">&middot;</span>
                <span class="text-muted-foreground">Registries: <strong class="text-foreground">{{ summaryStats.uniqueRegistries }}</strong></span>
            </div>
        </div>

        <div class="px-6 pb-6">
            <div class="rounded-xl border bg-card overflow-hidden">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b bg-muted/30">
                            <SortableHeader label="Project" sort-key="name" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader label="Country" sort-key="country" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader label="Methodology" sort-key="methodology" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader label="Sector" sort-key="sector" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader label="Sectoral Scope" sort-key="sectoralScope" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader label="Issuances" sort-key="credits" align="right" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader label="Status" sort-key="status" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <th class="text-left py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                                <span class="inline-flex items-center gap-1">
                                    SDGs
                                    <InfoTooltip text="UN Sustainable Development Goals this project contributes to. Hover over each icon for the full goal name." />
                                </span>
                            </th>
                            <SortableHeader label="Vintage" sort-key="vintage" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <th class="text-center py-2.5 px-3 text-xs font-medium text-muted-foreground uppercase tracking-wider"><span class="inline-flex items-center gap-1">Raw Data <InfoTooltip text="Raw Data on the blockchain" /></span></th>
                        </tr>
                    </thead>
                    <tbody class="divide-y">
                        <tr
                            v-for="p in paginated"
                            :key="p.id"
                            class="hover:bg-muted/30 transition-colors cursor-pointer"
                        >
                            <td class="py-3 px-4">
                                <NuxtLink :to="`/projects/${p.id}`" class="font-medium text-foreground hover:text-primary transition-colors">{{ p.name }}</NuxtLink>
                            </td>
                            <td class="py-3 px-4 text-muted-foreground">{{ p.flag }} {{ p.country }}</td>
                            <td class="py-3 px-4">
                                <span class="text-xs bg-muted rounded px-1.5 py-0.5">{{ p.methodology }}</span>
                            </td>
                            <td class="py-3 px-4">
                                <span class="text-xs text-muted-foreground">{{ p.sector }}</span>
                            </td>
                            <td class="py-3 px-4">
                                <span class="text-xs bg-muted rounded px-1.5 py-0.5 text-muted-foreground">{{ p.sectoralScope }}</span>
                            </td>
                            <td class="py-3 px-4 text-right tabular-nums font-medium">{{ p.creditsFormatted }}</td>
                            <td class="py-3 px-4">
                                <span :class="[statusColor[p.status] || 'bg-muted text-muted-foreground', 'text-xs font-medium rounded-full px-2 py-0.5']">
                                    {{ p.status }}
                                </span>
                            </td>
                            <td class="py-3 px-4">
                                <SdgBadges :ids="p.sdgs" :max="4" />
                            </td>
                            <td class="py-3 px-4 text-muted-foreground tabular-nums">{{ p.vintage }}</td>
                            <td class="py-3 px-3 text-center">
                                <button
                                    class="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                                    title="View Raw Data"
                                    @click.stop="viewVc(p)"
                                >
                                    <FileJson class="h-3.5 w-3.5" />
                                </button>
                            </td>
                        </tr>
                        <tr v-if="paginated.length === 0">
                            <td colspan="10" class="py-12 text-center text-sm text-muted-foreground">No projects match your filters</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <Pagination
                v-model:current-page="currentPage"
                :total-pages="totalPages"
                :total-items="filtered.length"
                :page-size="pageSize"
            />
        </div>

        <VcJsonViewer :open="vcViewerOpen" :title="vcViewerTitle" :data="vcViewerData" @close="vcViewerOpen = false" />
    </div>
</template>

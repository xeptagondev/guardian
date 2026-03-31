<script setup lang="ts">
import { Coins } from 'lucide-vue-next';
import type { FilterOption } from '~/components/shared/FilterBar.vue';
import { formatCredits } from '~/lib/format';

const { credits, total, filterOptions } = useCredits();

const allCredits = computed(() => credits.value.map(c => ({
    ...c,
    supplyFormatted: formatCredits(c.supply),
})));

const { searchQuery, currentPage, paginated, filtered, totalPages, pageSize, activeFilters, sortKey, sortDir, toggleSort, setFilter, clearFilters } =
    useFilteredPagination(allCredits, {
        searchFields: ['name', 'symbol', 'tokenId', 'project', 'registry'],
        pageSize: 8,
        defaultSort: { key: 'supply', dir: 'desc' },
    });

const filters = computed<FilterOption[]>(() => [
    { key: 'type', label: 'Token Type', options: filterOptions.value.types.map(t => ({ value: t, label: t })) },
    { key: 'registry', label: 'Registry', options: filterOptions.value.registries.map(r => ({ value: r, label: r })) },
]);

const typeColor: Record<string, string> = { Fungible: 'bg-stat-blue/10 text-stat-blue', 'Non-Fungible': 'bg-stat-amber/10 text-stat-amber' };
</script>

<template>
    <div class="space-y-0">
        <div class="px-6 pt-6 pb-4">
            <h1 class="text-2xl font-bold text-foreground">Credits</h1>
            <p class="text-sm text-muted-foreground mt-1">Carbon credit tokens issued on Hedera</p>
        </div>

        <div class="px-6 pb-3">
            <FilterBar v-model="searchQuery" :filters="filters" :active-filters="activeFilters" :result-count="filtered.length" :total-count="total" search-placeholder="Search by name, symbol, token ID..." @filter="setFilter" @clear="clearFilters" />
        </div>

        <div class="px-6 pb-6">
            <div class="rounded-xl border bg-card overflow-hidden">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b bg-muted/30">
                            <SortableHeader label="Token" sort-key="name" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader label="Symbol" sort-key="symbol" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader label="Type" sort-key="type" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader label="Supply" sort-key="supply" align="right" tooltip="Total token supply minted on Hedera. For fungible tokens this is the total tCO2e. For NFTs this is the number of unique serials." :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader label="Project" sort-key="project" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader label="Registry" sort-key="registry" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                        </tr>
                    </thead>
                    <tbody class="divide-y">
                        <tr v-for="c in paginated" :key="c.id" class="hover:bg-muted/30 transition-colors cursor-pointer">
                            <td class="py-3 px-4"><div><span class="font-medium text-foreground">{{ c.name }}</span><p class="text-[11px] text-muted-foreground/60 font-mono">{{ c.tokenId }}</p></div></td>
                            <td class="py-3 px-4 font-mono text-xs">{{ c.symbol }}</td>
                            <td class="py-3 px-4"><span :class="[typeColor[c.type], 'text-xs font-medium rounded-full px-2 py-0.5']">{{ c.type }}</span></td>
                            <td class="py-3 px-4 text-right tabular-nums font-medium">{{ c.supplyFormatted }}</td>
                            <td class="py-3 px-4 text-muted-foreground">{{ c.project }}</td>
                            <td class="py-3 px-4 text-muted-foreground">{{ c.registry }}</td>
                        </tr>
                        <tr v-if="paginated.length === 0"><td colspan="6" class="py-12 text-center text-sm text-muted-foreground">No credits match your filters</td></tr>
                    </tbody>
                </table>
            </div>
            <Pagination v-model:current-page="currentPage" :total-pages="totalPages" :total-items="filtered.length" :page-size="pageSize" />
        </div>
    </div>
</template>

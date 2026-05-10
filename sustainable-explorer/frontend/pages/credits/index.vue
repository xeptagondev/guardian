<script setup lang="ts">
import type { FilterOption } from '~/components/shared/FilterBar.vue';
import type { IssuanceSortKey, IssuanceSortDir } from '~/composables/api/useIssuancesApi';
import { formatCredits } from '~/lib/format';

const { t } = useI18n();
const { network } = useNetwork();
const route = useRoute();
const router = useRouter();

const pageSize = ref(route.query.limit ? parseInt(route.query.limit as string) : 20);
const currentPage = ref(route.query.page ? parseInt(route.query.page as string) : 1);
const searchQuery = ref((route.query.q as string) || '');
const sortKey = ref<IssuanceSortKey | null>((route.query.sort as IssuanceSortKey) || 'mintDate');
const sortDir = ref<IssuanceSortDir | null>((route.query.dir as IssuanceSortDir) || 'desc');

const RESERVED = new Set(['q', 'page', 'sort', 'dir', 'limit']);
const initialFilters: Record<string, string> = {};
for (const [k, v] of Object.entries(route.query)) {
    if (!RESERVED.has(k) && typeof v === 'string' && v) initialFilters[k] = v;
}
const activeFilters = ref<Record<string, string>>(initialFilters);

function syncUrl() {
    const query: Record<string, string> = {};
    if (searchQuery.value) query.q = searchQuery.value;
    if (currentPage.value > 1) query.page = String(currentPage.value);
    if (sortKey.value && sortDir.value && !(sortKey.value === 'mintDate' && sortDir.value === 'desc')) {
        query.sort = sortKey.value;
        query.dir = sortDir.value;
    }
    for (const [k, v] of Object.entries(activeFilters.value)) {
        if (v) query[k] = v;
    }
    router.replace({ query });
}

function toggleSort(key: IssuanceSortKey) {
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

watch(searchQuery, () => { currentPage.value = 1; syncUrl(); });
watch(currentPage, syncUrl);

const { issuances, meta, pending } = useIssuancesApi({
    page: currentPage,
    limit: pageSize,
    search: searchQuery,
    network,
    sortBy: sortKey,
    sortDir,
    filters: activeFilters,
});

function formatDate(dateStr: string | null): string {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

const typeLabel: Record<string, string> = {
    FUNGIBLE_COMMON: 'Fungible',
    NON_FUNGIBLE_UNIQUE: 'NFT',
};
const typeColor: Record<string, string> = {
    FUNGIBLE_COMMON: 'bg-stat-blue/10 text-stat-blue',
    NON_FUNGIBLE_UNIQUE: 'bg-stat-amber/10 text-stat-amber',
};

const filters = computed<FilterOption[]>(() => [
    {
        key: 'tokenType',
        label: t('credits.filters.tokenType'),
        options: [
            { value: 'FUNGIBLE_COMMON', label: 'Fungible' },
            { value: 'NON_FUNGIBLE_UNIQUE', label: 'Non-Fungible (NFT)' },
        ],
    },
]);
</script>

<template>
    <div class="space-y-0">
        <div class="px-6 pt-6 pb-4">
            <h1 class="text-2xl font-bold text-foreground">{{ $t('credits.title') }}</h1>
            <p class="text-sm text-muted-foreground mt-1">{{ $t('credits.subtitle') }}</p>
        </div>

        <div class="px-6 pb-3">
            <FilterBar
                v-model="searchQuery"
                :filters="filters"
                :active-filters="activeFilters"
                :result-count="meta.total"
                :total-count="meta.total"
                :search-placeholder="$t('credits.searchPlaceholder')"
                @filter="setFilter"
                @clear="clearFilters"
            />

            <!-- Date range filter -->
            <div class="flex items-center gap-2 mt-2.5 flex-wrap">
                <span class="text-[11px] text-muted-foreground">{{ $t('common.from') }}</span>
                <input
                    type="date"
                    :value="activeFilters.dateFrom || ''"
                    class="h-7 rounded-md border border-border bg-background px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                    @input="setFilter('dateFrom', ($event.target as HTMLInputElement).value)"
                />
                <span class="text-[11px] text-muted-foreground">{{ $t('common.to') }}</span>
                <input
                    type="date"
                    :value="activeFilters.dateTo || ''"
                    class="h-7 rounded-md border border-border bg-background px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                    @input="setFilter('dateTo', ($event.target as HTMLInputElement).value)"
                />
                <button
                    v-if="activeFilters.dateFrom || activeFilters.dateTo"
                    class="text-[11px] text-muted-foreground hover:text-foreground transition-colors"
                    @click="() => { setFilter('dateFrom', ''); setFilter('dateTo', ''); }"
                >
                    {{ $t('common.clear') }}
                </button>
            </div>
        </div>

        <div class="px-6 pb-6">
            <div class="rounded-xl border bg-card overflow-x-auto">
                <table class="w-full text-sm min-w-[800px]">
                    <thead>
                        <tr class="border-b bg-muted/30">
                            <SortableHeader :label="$t('credits.columns.date')" sort-key="mintDate" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader :label="$t('credits.columns.token')" sort-key="tokenId" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader :label="$t('credits.columns.amount')" sort-key="amount" align="right" :tooltip="$t('credits.amountTooltip')" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <SortableHeader :label="$t('credits.columns.project')" sort-key="projectName" :active-sort-key="sortKey as string" :sort-dir="sortDir" @sort="toggleSort($event as any)" />
                            <th class="text-left py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">{{ $t('credits.columns.methodology') }}</th>
                            <th class="text-left py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">{{ $t('credits.columns.type') }}</th>
                            <th class="text-left py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">{{ $t('credits.columns.registry') }}</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y">
                        <!-- Skeleton rows -->
                        <tr v-if="pending" v-for="i in pageSize" :key="`skel-${i}`" class="animate-pulse">
                            <td class="py-3 px-4"><div class="h-4 w-24 rounded bg-muted" /></td>
                            <td class="py-3 px-4">
                                <div class="h-4 w-28 rounded bg-muted mb-1" />
                                <div class="h-3 w-20 rounded bg-muted" />
                            </td>
                            <td class="py-3 px-4"><div class="h-4 w-16 rounded bg-muted ml-auto" /></td>
                            <td class="py-3 px-4"><div class="h-4 w-32 rounded bg-muted" /></td>
                            <td class="py-3 px-4"><div class="h-4 w-20 rounded bg-muted" /></td>
                            <td class="py-3 px-4"><div class="h-5 w-16 rounded-full bg-muted" /></td>
                            <td class="py-3 px-4"><div class="h-4 w-24 rounded bg-muted" /></td>
                        </tr>
                        <!-- Data rows -->
                        <tr
                            v-else
                            v-for="item in issuances"
                            :key="item.mintConsensusTimestamp"
                            class="hover:bg-muted/30 transition-colors"
                        >
                            <td class="py-3 px-4 text-xs text-muted-foreground whitespace-nowrap">
                                {{ formatDate(item.mintDate) }}
                            </td>
                            <td class="py-3 px-4">
                                <div class="font-medium text-foreground text-sm leading-tight">
                                    {{ item.tokenName || item.tokenId || '—' }}
                                </div>
                                <div class="font-mono text-[10px] text-muted-foreground/60 mt-0.5 flex items-center gap-1.5">
                                    <span>{{ item.tokenId || '' }}</span>
                                    <span v-if="item.symbol" class="rounded bg-muted px-1 py-px text-muted-foreground font-sans">{{ item.symbol }}</span>
                                </div>
                            </td>
                            <td class="py-3 px-4 text-right tabular-nums font-medium text-foreground whitespace-nowrap">
                                {{ formatCredits(item.amount) }}
                            </td>
                            <td class="py-3 px-4">
                                <NuxtLink
                                    v-if="item.projectId"
                                    :to="`/projects/${item.projectId}`"
                                    class="text-sm text-foreground hover:text-primary transition-colors line-clamp-2"
                                >
                                    {{ item.projectName || item.projectId }}
                                </NuxtLink>
                                <span v-else class="text-sm text-muted-foreground">—</span>
                            </td>
                            <td class="py-3 px-4">
                                <span v-if="item.methodology" class="text-xs text-muted-foreground">
                                    {{ item.methodology }}
                                </span>
                                <span v-else class="text-xs text-muted-foreground/40">—</span>
                            </td>
                            <td class="py-3 px-4">
                                <span
                                    v-if="item.tokenType"
                                    :class="[typeColor[item.tokenType] || 'bg-muted text-muted-foreground', 'text-xs font-medium rounded-full px-2 py-0.5 whitespace-nowrap']"
                                >
                                    {{ typeLabel[item.tokenType] || item.tokenType }}
                                </span>
                                <span v-else class="text-xs text-muted-foreground/40">—</span>
                            </td>
                            <td class="py-3 px-4 text-xs text-muted-foreground">
                                {{ item.registry || '—' }}
                            </td>
                        </tr>
                        <tr v-if="!pending && issuances.length === 0">
                            <td colspan="7" class="py-12 text-center text-sm text-muted-foreground">{{ $t('credits.noMatch') }}</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <Pagination
                v-model:current-page="currentPage"
                v-model:page-size="pageSize"
                :total-pages="meta.totalPages"
                :total-items="meta.total"
            />
        </div>
    </div>
</template>

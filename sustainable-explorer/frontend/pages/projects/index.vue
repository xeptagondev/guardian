<script setup lang="ts">
import { FolderKanban, Search, RefreshCw, MapPin, Calendar } from 'lucide-vue-next';
import { useProjectsApi } from '~/composables/api/useProjectsApi';

const { network } = useNetwork();

const page = ref(1);
const limit = ref(20);
const search = ref('');
const country = ref<string | null>(null);
const status = ref<string | null>(null);
const vintage = ref<string | null>(null);
const sector = ref<string | null>(null);
const projectType = ref<string | null>(null);

watch([search, country, status, vintage, sector, projectType], () => {
    page.value = 1;
});

const { data, pending, refresh } = useProjectsApi({
    network,
    page, limit, search, country, status, vintage, sector, projectType,
});

const rows = computed(() => data.value?.data ?? []);
const meta = computed(() => data.value?.meta ?? { page: 1, limit: 20, total: 0, totalPages: 1 });

// Build filter dropdowns from the current page's data — cheap, good enough
// without a dedicated /facets endpoint.
const distinct = (key: 'country' | 'status' | 'vintage' | 'sector' | 'projectType') =>
    Array.from(new Set(rows.value.map((p) => p[key]).filter((v): v is string => !!v))).sort();

const countryOptions    = computed(() => distinct('country'));
const statusOptions     = computed(() => distinct('status'));
const vintageOptions    = computed(() => distinct('vintage'));
const sectorOptions     = computed(() => distinct('sector'));
const projectTypeOptions = computed(() => distinct('projectType'));

function clearFilters() {
    search.value = '';
    country.value = null;
    status.value = null;
    vintage.value = null;
    sector.value = null;
    projectType.value = null;
}

const statusBadge = (s: string | null) => {
    const v = (s ?? '').toLowerCase();
    if (v.includes('approved') || v.includes('issuing') || v.includes('verified') || v.includes('completed')) return 'bg-stat-green/10 text-stat-green';
    if (v.includes('pending') || v.includes('validation') || v.includes('review')) return 'bg-stat-amber/10 text-stat-amber';
    if (v.includes('rejected') || v.includes('failed')) return 'bg-stat-rose/10 text-stat-rose';
    return 'bg-muted text-muted-foreground';
};

function dash(v: unknown): string {
    return v === null || v === undefined || v === '' ? '—' : String(v);
}
</script>

<template>
    <div class="space-y-0">
        <!-- Header -->
        <div class="px-6 pt-6 pb-4">
            <h1 class="text-2xl font-bold text-foreground flex items-center gap-2">
                <FolderKanban class="h-6 w-6 text-primary" />
                Projects
            </h1>
            <p class="text-sm text-muted-foreground mt-1">
                All canonical projects extracted from on-chain VCs across decoded methodologies.
            </p>
        </div>

        <!-- Filters -->
        <div class="px-6 pb-3 space-y-2">
            <div class="flex items-center gap-2 flex-wrap">
                <div class="relative flex-1 min-w-[260px] max-w-[420px]">
                    <Search class="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <input
                        v-model="search"
                        type="text"
                        placeholder="Search by name, ID, or description…"
                        class="w-full pl-9 pr-3 py-2 text-sm rounded-md border bg-background focus:outline-none focus:ring-1 focus:ring-primary"
                    />
                </div>

                <select v-model="country" class="text-sm rounded-md border bg-background px-2.5 py-2">
                    <option :value="null">All countries</option>
                    <option v-for="o in countryOptions" :key="o" :value="o">{{ o }}</option>
                </select>
                <select v-model="status" class="text-sm rounded-md border bg-background px-2.5 py-2">
                    <option :value="null">All statuses</option>
                    <option v-for="o in statusOptions" :key="o" :value="o">{{ o }}</option>
                </select>
                <select v-model="vintage" class="text-sm rounded-md border bg-background px-2.5 py-2">
                    <option :value="null">All vintages</option>
                    <option v-for="o in vintageOptions" :key="o" :value="o">{{ o }}</option>
                </select>
                <select v-model="sector" class="text-sm rounded-md border bg-background px-2.5 py-2">
                    <option :value="null">All sectors</option>
                    <option v-for="o in sectorOptions" :key="o" :value="o">{{ o }}</option>
                </select>
                <select v-model="projectType" class="text-sm rounded-md border bg-background px-2.5 py-2">
                    <option :value="null">All types</option>
                    <option v-for="o in projectTypeOptions" :key="o" :value="o">{{ o }}</option>
                </select>

                <button
                    v-if="search || country || status || vintage || sector || projectType"
                    class="text-xs text-muted-foreground hover:text-foreground inline-flex items-center"
                    @click="clearFilters"
                >
                    Clear
                </button>
                <button
                    class="ml-auto text-xs text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
                    :disabled="pending"
                    @click="refresh()"
                >
                    <RefreshCw class="h-3.5 w-3.5" :class="pending ? 'animate-spin' : ''" />
                    Refresh
                </button>
            </div>
            <div class="text-xs text-muted-foreground">
                <strong class="text-foreground">{{ meta.total }}</strong> project{{ meta.total === 1 ? '' : 's' }}
                <span class="mx-1">·</span>
                page {{ meta.page }} of {{ meta.totalPages }}
            </div>
        </div>

        <!-- Table -->
        <div class="px-6 pb-6">
            <div class="rounded-xl border bg-card overflow-x-auto">
                <table class="w-full text-sm min-w-[1000px]">
                    <thead>
                        <tr class="border-b bg-muted/30 text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                            <th class="text-left py-2.5 px-4">Project</th>
                            <th class="text-left py-2.5 px-4">Country / Region</th>
                            <th class="text-left py-2.5 px-4">Methodology</th>
                            <th class="text-left py-2.5 px-4">Sector</th>
                            <th class="text-left py-2.5 px-4">Type</th>
                            <th class="text-left py-2.5 px-4">Vintage</th>
                            <th class="text-left py-2.5 px-4">Period</th>
                            <th class="text-left py-2.5 px-4">Status</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y">
                        <tr v-if="pending && rows.length === 0">
                            <td colspan="8" class="py-12 text-center text-sm text-muted-foreground">
                                Loading projects…
                            </td>
                        </tr>
                        <tr v-else-if="rows.length === 0">
                            <td colspan="8" class="py-12 text-center text-sm text-muted-foreground">
                                <FolderKanban class="h-8 w-8 mx-auto mb-2 opacity-30" />
                                <p class="font-medium text-foreground">No projects yet</p>
                                <p class="max-w-md mx-auto mt-1 text-xs">
                                    Either no project VCs have been extracted yet on this network, or
                                    your filters returned no matches.
                                </p>
                            </td>
                        </tr>
                        <tr
                            v-for="p in rows"
                            v-else
                            :key="p.id"
                            class="hover:bg-muted/30 transition-colors cursor-pointer"
                            @click="navigateTo(`/projects/${p.id}`)"
                        >
                            <td class="py-3 px-4">
                                <NuxtLink
                                    :to="`/projects/${p.id}`"
                                    class="font-medium text-foreground hover:text-primary transition-colors break-words"
                                >
                                    {{ p.name || p.projectId || `Project #${p.id}` }}
                                </NuxtLink>
                                <div v-if="p.projectId && p.name" class="text-[11px] font-mono text-muted-foreground truncate max-w-[280px]">
                                    {{ p.projectId }}
                                </div>
                            </td>
                            <td class="py-3 px-4">
                                <div class="flex items-center gap-1.5 text-foreground">
                                    <CountryFlag v-if="p.countryCode" :code="p.countryCode" size="sm" />
                                    <MapPin v-else class="h-3 w-3 text-muted-foreground" />
                                    <span>{{ dash(p.country) }}<template v-if="p.region">, {{ p.region }}</template></span>
                                </div>
                            </td>
                            <td class="py-3 px-4">
                                <code v-if="p.methodologyTag" class="text-[11px] bg-muted rounded px-1.5 py-0.5 font-mono">
                                    {{ p.methodologyTag }}
                                </code>
                                <span v-else class="text-muted-foreground">—</span>
                            </td>
                            <td class="py-3 px-4 text-muted-foreground">{{ dash(p.sector) }}</td>
                            <td class="py-3 px-4 text-muted-foreground">{{ dash(p.projectType) }}</td>
                            <td class="py-3 px-4 text-foreground tabular-nums">{{ dash(p.vintage) }}</td>
                            <td class="py-3 px-4 text-xs text-muted-foreground">
                                <div v-if="p.startDate || p.endDate" class="flex items-center gap-1">
                                    <Calendar class="h-3 w-3" />
                                    <span>{{ p.startDate ?? '?' }} → {{ p.endDate ?? '?' }}</span>
                                </div>
                                <span v-else>—</span>
                            </td>
                            <td class="py-3 px-4">
                                <span
                                    v-if="p.status"
                                    :class="[statusBadge(p.status), 'inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium']"
                                >
                                    {{ p.status }}
                                </span>
                                <span v-else class="text-muted-foreground">—</span>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <div
                v-if="meta.totalPages > 1"
                class="flex items-center justify-between mt-3 text-xs text-muted-foreground"
            >
                <span>
                    Showing {{ (meta.page - 1) * meta.limit + 1 }} – {{ Math.min(meta.page * meta.limit, meta.total) }} of {{ meta.total }}
                </span>
                <div class="flex items-center gap-1">
                    <button
                        class="px-2 py-1 rounded hover:bg-muted disabled:opacity-50"
                        :disabled="page <= 1"
                        @click="page = Math.max(1, page - 1)"
                    >
                        Prev
                    </button>
                    <button
                        class="px-2 py-1 rounded hover:bg-muted disabled:opacity-50"
                        :disabled="page >= meta.totalPages"
                        @click="page = Math.min(meta.totalPages, page + 1)"
                    >
                        Next
                    </button>
                </div>
            </div>
        </div>
    </div>
</template>

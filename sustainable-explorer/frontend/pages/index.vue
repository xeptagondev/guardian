<script setup lang="ts">
import { ref, computed } from 'vue';
import { onClickOutside } from '@vueuse/core';
import {
    Globe,
    Table2,
    Building2,
    Shield,
    FolderKanban,
    Coins,
    TrendingUp,
    FileText,
    ArrowUpRight,
    ArrowDownRight,
    Clock,
    CheckCircle2,
    Plus,
    Zap,
    ChevronDown,
    X,
    Check,
} from 'lucide-vue-next';
import { formatCredits } from '~/lib/format';

const viewMode = ref<'map' | 'table'>('map');
const chartMode = ref<'projects' | 'credits'>('projects');
const selectedCountry = ref<string | null>(null);

// --- Filter dropdowns ---
const selectedDeveloper = ref<string>('All Developers');
const selectedRegistry = ref<string>('All Registries');

const dashboardFilters = computed(() => ({
    developer: selectedDeveloper.value,
    registry: selectedRegistry.value,
}));

const {
    stats,
    hasActiveFilter,
    countries,
    mapCountries,
    mapPoints,
    registries,
    issuanceMonths,
    issuanceMax,
    issuanceTotal,
    recentActivity,
    sectorBreakdown,
    registryBreakdown,
    developerOptions,
    registryOptions,
    getCountryDetail,
} = useDashboard(dashboardFilters);

const sectorChartSegments = computed(() =>
    sectorBreakdown.value.map(s => ({
        label: s.label,
        value: chartMode.value === 'projects' ? s.projectCount : s.creditCount,
        color: s.color,
    })),
);

const registryChartSegments = computed(() =>
    registryBreakdown.value.map(s => ({
        label: s.label,
        value: chartMode.value === 'projects' ? s.projectCount : s.creditCount,
        color: s.color,
    })),
);

const sectorTotal = computed(() => sectorChartSegments.value.reduce((sum, s) => sum + s.value, 0));
const registryTotal = computed(() => registryChartSegments.value.reduce((sum, s) => sum + s.value, 0));

const developerDropdownOpen = ref(false);
const registryDropdownOpen = ref(false);
const developerRef = ref<HTMLElement | null>(null);
const registryRef = ref<HTMLElement | null>(null);

onClickOutside(developerRef, () => { developerDropdownOpen.value = false; });
onClickOutside(registryRef, () => { registryDropdownOpen.value = false; });

function selectDeveloper(val: string) {
    selectedDeveloper.value = val;
    developerDropdownOpen.value = false;
}
function selectRegistry(val: string) {
    selectedRegistry.value = val;
    registryDropdownOpen.value = false;
}
function clearFilters() {
    selectedDeveloper.value = 'All Developers';
    selectedRegistry.value = 'All Registries';
}

const activeDetail = computed(() => {
    if (!selectedCountry.value) return null;
    return getCountryDetail(selectedCountry.value);
});

function onCountryClick(code: string) {
    selectedCountry.value = selectedCountry.value === code ? null : code;
}

// Activity icons mapping
const activityIcons: Record<string, any> = {
    project: Plus,
    credit: Coins,
    policy: CheckCircle2,
    verification: Shield,
    registry: Building2,
    retirement: Zap,
};

const activityColors: Record<string, string> = {
    project: 'text-stat-green',
    credit: 'text-stat-amber',
    policy: 'text-stat-blue',
    verification: 'text-primary',
    registry: 'text-stat-rose',
    retirement: 'text-stat-amber',
};

// --- Stat cards ---
const filteredStats = computed(() => {
    return [
        {
            label: 'Registries',
            value: String(stats.value.registries),
            change: hasActiveFilter.value ? '' : '+2',
            trend: 'up',
            sub: 'Standard Registries',
            tooltip: 'Number of unique Standard Registries (e.g., Verra, Gold Standard) that have published projects matching the current filters.',
            icon: Shield,
            accent: 'text-stat-blue',
            accentBg: 'bg-stat-blue/10',
            to: '/registries',
        },
        {
            label: 'Methodologies',
            value: String(stats.value.methodologies),
            change: hasActiveFilter.value ? '' : '+5',
            trend: 'up',
            sub: 'Published policies',
            tooltip: 'Total number of unique published policy methodologies across all matching registries. Each methodology defines the rules for project verification.',
            icon: FileText,
            accent: 'text-stat-green',
            accentBg: 'bg-stat-green/10',
            to: '/methodologies',
        },
        {
            label: 'Projects',
            value: stats.value.projects.toLocaleString(),
            change: hasActiveFilter.value ? '' : '+18',
            trend: 'up',
            sub: 'Active verified projects',
            tooltip: 'Count of sustainability projects that have been registered and verified on the Guardian network matching the current filters.',
            icon: FolderKanban,
            accent: 'text-stat-amber',
            accentBg: 'bg-stat-amber/10',
            to: '/projects',
        },
        {
            label: 'Total Credits',
            value: formatCredits(stats.value.totalCredits),
            change: hasActiveFilter.value ? '' : '+12.3%',
            trend: 'up',
            sub: 'tCO2e issued on-chain',
            tooltip: 'Sum of all carbon credits (in tonnes of CO2 equivalent) issued on-chain across matching projects. Includes both fungible and non-fungible tokens.',
            icon: Coins,
            accent: 'text-stat-rose',
            accentBg: 'bg-stat-rose/10',
            to: '/credits',
        },
    ];
});
</script>

<template>
    <div class="space-y-0">
        <!-- Header -->
        <div class="px-6 pt-6 pb-5">
            <div class="flex items-start justify-between">
                <div>
                    <h1 class="text-2xl font-bold text-foreground">Dashboard</h1>
                    <p class="text-sm text-muted-foreground mt-1">Overview of the Hedera Guardian sustainability network</p>
                </div>

                <!-- Filter dropdowns (right-aligned) -->
                <div class="flex items-center gap-2 shrink-0">
                <InfoTooltip text="Filter all dashboard data by project developer and/or registry. All cards, charts, map, and tables update to show only matching projects." />
                <!-- Developer dropdown -->
                <div ref="developerRef" class="relative">
                    <button
                        class="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors"
                        :class="selectedDeveloper !== 'All Developers'
                            ? 'border-primary/30 bg-primary/5 text-primary'
                            : 'border-border text-muted-foreground hover:bg-muted hover:text-foreground'"
                        @click="developerDropdownOpen = !developerDropdownOpen"
                    >
                        <span>{{ selectedDeveloper }}</span>
                        <ChevronDown
                            class="h-3 w-3 opacity-50 transition-transform"
                            :class="developerDropdownOpen ? 'rotate-180' : ''"
                        />
                    </button>
                    <Transition
                        enter-active-class="transition ease-out duration-100"
                        enter-from-class="opacity-0 scale-95"
                        enter-to-class="opacity-100 scale-100"
                        leave-active-class="transition ease-in duration-75"
                        leave-from-class="opacity-100 scale-100"
                        leave-to-class="opacity-0 scale-95"
                    >
                        <div
                            v-if="developerDropdownOpen"
                            class="absolute left-0 top-full mt-1 w-48 rounded-md border bg-popover p-1 shadow-md z-50"
                        >
                            <button
                                v-for="opt in developerOptions"
                                :key="opt"
                                class="flex w-full items-center gap-2 rounded-sm px-2.5 py-1.5 text-xs transition-colors hover:bg-accent hover:text-accent-foreground"
                                @click="selectDeveloper(opt)"
                            >
                                <span class="flex-1 text-left">{{ opt }}</span>
                                <Check
                                    v-if="selectedDeveloper === opt"
                                    class="h-3 w-3 text-primary"
                                />
                            </button>
                        </div>
                    </Transition>
                </div>

                <!-- Registry dropdown -->
                <div ref="registryRef" class="relative">
                    <button
                        class="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors"
                        :class="selectedRegistry !== 'All Registries'
                            ? 'border-primary/30 bg-primary/5 text-primary'
                            : 'border-border text-muted-foreground hover:bg-muted hover:text-foreground'"
                        @click="registryDropdownOpen = !registryDropdownOpen"
                    >
                        <span>{{ selectedRegistry }}</span>
                        <ChevronDown
                            class="h-3 w-3 opacity-50 transition-transform"
                            :class="registryDropdownOpen ? 'rotate-180' : ''"
                        />
                    </button>
                    <Transition
                        enter-active-class="transition ease-out duration-100"
                        enter-from-class="opacity-0 scale-95"
                        enter-to-class="opacity-100 scale-100"
                        leave-active-class="transition ease-in duration-75"
                        leave-from-class="opacity-100 scale-100"
                        leave-to-class="opacity-0 scale-95"
                    >
                        <div
                            v-if="registryDropdownOpen"
                            class="absolute left-0 top-full mt-1 w-48 rounded-md border bg-popover p-1 shadow-md z-50"
                        >
                            <button
                                v-for="opt in registryOptions"
                                :key="opt"
                                class="flex w-full items-center gap-2 rounded-sm px-2.5 py-1.5 text-xs transition-colors hover:bg-accent hover:text-accent-foreground"
                                @click="selectRegistry(opt)"
                            >
                                <span class="flex-1 text-left">{{ opt }}</span>
                                <Check
                                    v-if="selectedRegistry === opt"
                                    class="h-3 w-3 text-primary"
                                />
                            </button>
                        </div>
                    </Transition>
                </div>

                <!-- Clear button -->
                <Transition
                    enter-active-class="transition ease-out duration-100"
                    enter-from-class="opacity-0"
                    enter-to-class="opacity-100"
                    leave-active-class="transition ease-in duration-75"
                    leave-from-class="opacity-100"
                    leave-to-class="opacity-0"
                >
                    <button
                        v-if="hasActiveFilter"
                        class="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
                        @click="clearFilters"
                    >
                        <X class="h-3 w-3" />
                        <span>Clear</span>
                    </button>
                </Transition>
            </div>
            </div>
        </div>

        <!-- Stat Cards -->
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 px-6 pb-6">
            <NuxtLink
                v-for="s in filteredStats"
                :key="s.label"
                :to="s.to"
                class="group rounded-xl border bg-card p-4 transition-all hover:shadow-md hover:border-border/80"
            >
                <div class="flex items-center justify-between mb-3">
                    <span class="inline-flex items-center gap-1 text-xs font-medium uppercase tracking-wider text-muted-foreground">
                        {{ s.label }}
                        <InfoTooltip :text="s.tooltip" />
                    </span>
                    <div :class="[s.accentBg, 'rounded-lg p-1.5 transition-transform group-hover:scale-110']">
                        <component :is="s.icon" :class="[s.accent, 'h-3.5 w-3.5']" />
                    </div>
                </div>
                <div class="flex items-baseline gap-2">
                    <span class="text-2xl font-bold text-foreground">{{ s.value }}</span>
                    <span v-if="s.change" class="flex items-center gap-0.5 text-xs font-medium text-stat-green">
                        <ArrowUpRight class="h-3 w-3" />
                        {{ s.change }}
                    </span>
                </div>
                <p class="text-xs text-muted-foreground mt-1">{{ s.sub }}</p>
            </NuxtLink>
        </div>

        <!-- Project Distribution -->
        <div class="border-t">
            <div class="flex items-center justify-between px-6 py-4">
                <div class="flex items-center gap-4">
                    <div>
                        <h2 class="text-base font-semibold text-foreground inline-flex items-center gap-1.5">Project Distribution <InfoTooltip text="Countries are colored by project count. Darker green = more projects. Click a country to see detailed breakdown. Small dots show individual project locations." /></h2>
                        <p class="text-xs text-muted-foreground mt-0.5">Geographic spread of verified projects</p>
                    </div>
                    <NuxtLink to="/projects" class="text-xs font-medium text-primary hover:underline">View all projects</NuxtLink>
                </div>
                <div class="flex items-center rounded-lg border p-0.5">
                    <button
                        class="flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition-colors"
                        :class="viewMode === 'map'
                            ? 'bg-foreground text-background shadow-sm'
                            : 'text-muted-foreground hover:text-foreground'"
                        @click="viewMode = 'map'"
                    >
                        <Globe class="h-3.5 w-3.5" />
                        Map
                    </button>
                    <button
                        class="flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition-colors"
                        :class="viewMode === 'table'
                            ? 'bg-foreground text-background shadow-sm'
                            : 'text-muted-foreground hover:text-foreground'"
                        @click="viewMode = 'table'"
                    >
                        <Table2 class="h-3.5 w-3.5" />
                        Table
                    </button>
                </div>
            </div>
            <div class="px-6 pb-6">
                <!-- Map view with side panel -->
                <div v-if="viewMode === 'map'" class="rounded-xl border bg-card overflow-hidden">
                    <div class="flex" :class="activeDetail ? 'h-[28rem]' : 'h-96'">
                        <!-- Map -->
                        <div class="flex-1 relative">
                            <ProjectMap :countries="mapCountries" :points="mapPoints" @country-click="onCountryClick" />
                        </div>

                        <!-- Side Panel -->
                        <Transition
                            enter-active-class="transition-all duration-300 ease-out"
                            enter-from-class="w-0 opacity-0"
                            enter-to-class="w-80 opacity-100"
                            leave-active-class="transition-all duration-200 ease-in"
                            leave-from-class="w-80 opacity-100"
                            leave-to-class="w-0 opacity-0"
                        >
                            <div v-if="activeDetail" class="w-80 shrink-0 border-l overflow-y-auto bg-card">
                                <div class="p-4 space-y-5">
                                    <!-- Country header -->
                                    <div class="flex items-center justify-between">
                                        <div class="flex items-center gap-2">
                                            <span class="text-xl">{{ activeDetail.flag }}</span>
                                            <h3 class="text-sm font-semibold text-foreground">{{ activeDetail.name }}</h3>
                                        </div>
                                        <button
                                            class="flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                                            @click="selectedCountry = null"
                                        >
                                            <svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                                        </button>
                                    </div>

                                    <!-- Key stats -->
                                    <div class="text-center">
                                        <div class="text-3xl font-bold text-primary">{{ activeDetail.projects.toLocaleString() }}</div>
                                        <div class="text-[11px] text-muted-foreground mt-0.5">Active Projects</div>
                                    </div>

                                    <div class="grid grid-cols-2 gap-3">
                                        <div class="text-center">
                                            <div class="text-lg font-bold text-primary">{{ activeDetail.totalReduction }}</div>
                                            <div class="text-[10px] text-muted-foreground">MtCO2 Total Reduction</div>
                                        </div>
                                        <div class="text-center">
                                            <div class="text-lg font-bold text-primary">{{ activeDetail.annualReduction }}</div>
                                            <div class="text-[10px] text-muted-foreground">MtCO2 Annual Est.</div>
                                        </div>
                                    </div>

                                    <!-- Sector donut -->
                                    <div>
                                        <h4 class="text-xs font-semibold text-foreground mb-3">Sector</h4>
                                        <div class="flex items-start gap-3">
                                            <DonutChart :segments="activeDetail.sectors" :size="90" />
                                            <div class="space-y-1.5 flex-1 min-w-0">
                                                <div v-for="s in activeDetail.sectors" :key="s.label" class="flex items-center gap-2">
                                                    <span class="h-2 w-2 shrink-0 rounded-full" :style="{ backgroundColor: s.color }" />
                                                    <span class="text-[11px] text-muted-foreground truncate">
                                                        <strong class="text-foreground">{{ s.value }}%</strong> {{ s.label }}
                                                    </span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Registry breakdown -->
                                    <div>
                                        <h4 class="text-xs font-semibold text-foreground mb-3">Registry</h4>
                                        <div class="flex items-center justify-between gap-2">
                                            <div v-for="r in activeDetail.registries" :key="r.name" class="text-center flex-1">
                                                <div class="text-base font-bold text-primary">{{ r.pct }}<span class="text-xs text-muted-foreground">%</span></div>
                                                <div class="text-[10px] text-muted-foreground leading-tight mt-0.5">{{ r.name }}</div>
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Credits -->
                                    <div class="pt-2 border-t">
                                        <div class="flex items-center justify-between">
                                            <span class="text-xs text-muted-foreground">Total Credits Issued</span>
                                            <span class="text-sm font-bold text-foreground">{{ activeDetail.credits }} tCO2e</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </Transition>
                    </div>
                </div>

                <!-- Table view -->
                <div v-else class="rounded-xl border bg-card overflow-hidden">
                    <table class="w-full text-sm">
                        <thead>
                            <tr class="border-b bg-muted/30">
                                <th class="text-left py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">Country</th>
                                <th class="text-right py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">Projects</th>
                                <th class="text-right py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">Credits Issued</th>
                                <th class="text-right py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">Methodologies</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y">
                            <tr
                                v-for="c in countries"
                                :key="c.name"
                                class="hover:bg-muted/30 transition-colors"
                            >
                                <td class="py-2.5 px-4">
                                    <span class="flex items-center gap-2">
                                        <span class="text-base">{{ c.flag }}</span>
                                        <span class="font-medium text-foreground">{{ c.name }}</span>
                                    </span>
                                </td>
                                <td class="py-2.5 px-4 text-right tabular-nums">{{ c.projects }}</td>
                                <td class="py-2.5 px-4 text-right tabular-nums">{{ c.credits }}</td>
                                <td class="py-2.5 px-4 text-right tabular-nums">{{ c.methodologies }}</td>
                            </tr>
                            <tr v-if="countries.length === 0">
                                <td colspan="4" class="py-8 text-center text-sm text-muted-foreground">No countries match the selected filters</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Sector & Registry Breakdown -->
        <div class="border-t">
            <div class="flex items-center justify-between px-6 py-4">
                <div>
                    <h2 class="text-base font-semibold text-foreground inline-flex items-center gap-1.5">Sector & Registry Breakdown <InfoTooltip text="Distribution of projects and credits by sector and registry. Toggle between project count and credit volume. Reflects current developer/registry filters." /></h2>
                    <p class="text-xs text-muted-foreground mt-0.5">Distribution of projects and credits by sector and registry</p>
                </div>
                <div class="flex items-center rounded-lg border p-0.5">
                    <button
                        class="flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition-colors"
                        :class="chartMode === 'projects'
                            ? 'bg-foreground text-background shadow-sm'
                            : 'text-muted-foreground hover:text-foreground'"
                        @click="chartMode = 'projects'"
                    >
                        Projects
                    </button>
                    <button
                        class="flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition-colors"
                        :class="chartMode === 'credits'
                            ? 'bg-foreground text-background shadow-sm'
                            : 'text-muted-foreground hover:text-foreground'"
                        @click="chartMode = 'credits'"
                    >
                        Credits
                    </button>
                </div>
            </div>
            <div class="px-6 pb-6">
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <!-- Sector Breakdown -->
                    <div class="rounded-xl border bg-card p-5">
                        <h3 class="text-sm font-semibold text-foreground mb-4">By Sector</h3>
                        <div class="flex items-start gap-5">
                            <DonutChart :segments="sectorChartSegments" :size="140" />
                            <div class="space-y-2 flex-1 min-w-0 pt-1">
                                <div v-for="s in sectorBreakdown" :key="s.label" class="flex items-center gap-2">
                                    <span class="h-2.5 w-2.5 shrink-0 rounded-full" :style="{ backgroundColor: s.color }" />
                                    <span class="text-xs text-muted-foreground truncate flex-1">{{ s.label }}</span>
                                    <span class="text-xs font-medium text-foreground tabular-nums shrink-0">
                                        {{ sectorTotal > 0 ? ((chartMode === 'projects' ? s.projectCount : s.creditCount) / sectorTotal * 100).toFixed(1) : '0.0' }}%
                                    </span>
                                    <span class="text-xs text-muted-foreground tabular-nums shrink-0">
                                        {{ chartMode === 'projects' ? `${s.projectCount} projects` : `${formatCredits(s.creditCount)} tCO2e` }}
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Registry Breakdown -->
                    <div class="rounded-xl border bg-card p-5">
                        <h3 class="text-sm font-semibold text-foreground mb-4">By Registry</h3>
                        <div class="flex items-start gap-5">
                            <DonutChart :segments="registryChartSegments" :size="140" />
                            <div class="space-y-2 flex-1 min-w-0 pt-1">
                                <div v-for="s in registryBreakdown" :key="s.label" class="flex items-center gap-2">
                                    <span class="h-2.5 w-2.5 shrink-0 rounded-full" :style="{ backgroundColor: s.color }" />
                                    <span class="text-xs text-muted-foreground truncate flex-1">{{ s.label }}</span>
                                    <span class="text-xs font-medium text-foreground tabular-nums shrink-0">
                                        {{ registryTotal > 0 ? ((chartMode === 'projects' ? s.projectCount : s.creditCount) / registryTotal * 100).toFixed(1) : '0.0' }}%
                                    </span>
                                    <span class="text-xs text-muted-foreground tabular-nums shrink-0">
                                        {{ chartMode === 'projects' ? `${s.projectCount} projects` : `${formatCredits(s.creditCount)} tCO2e` }}
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Two-column: Registries + Issuance -->
        <div class="border-t">
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-0">
                <!-- Top Registries -->
                <div class="lg:border-r">
                    <div class="flex items-center justify-between px-6 py-4">
                        <div>
                            <h2 class="text-base font-semibold text-foreground inline-flex items-center gap-1.5">Top Registries <InfoTooltip text="Ranked by project count. Policies = unique methodologies published. Credits = total tCO2e issued on-chain by this registry." /></h2>
                            <p class="text-xs text-muted-foreground mt-0.5">Most active by policy and project count</p>
                        </div>
                        <NuxtLink to="/registries" class="text-xs font-medium text-primary hover:underline">View all</NuxtLink>
                    </div>
                    <div class="px-6 pb-6">
                        <div class="rounded-xl border bg-card overflow-hidden">
                            <table class="w-full text-sm">
                                <thead>
                                    <tr class="border-b bg-muted/30">
                                        <th class="text-left py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">Name</th>
                                        <th class="text-right py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">Policies</th>
                                        <th class="text-right py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">Projects</th>
                                        <th class="text-right py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">Credits</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y">
                                    <tr
                                        v-for="org in registries"
                                        :key="org.name"
                                        class="hover:bg-muted/30 transition-colors cursor-pointer"
                                    >
                                        <td class="py-2.5 px-4">
                                            <NuxtLink to="/registries" class="font-medium text-foreground hover:text-primary transition-colors">{{ org.name }}</NuxtLink>
                                        </td>
                                        <td class="py-2.5 px-4 text-right tabular-nums">{{ org.policies }}</td>
                                        <td class="py-2.5 px-4 text-right tabular-nums">{{ org.projects }}</td>
                                        <td class="py-2.5 px-4 text-right tabular-nums text-muted-foreground">{{ org.credits }}</td>
                                    </tr>
                                    <tr v-if="registries.length === 0">
                                        <td colspan="4" class="py-8 text-center text-sm text-muted-foreground">No registries match the selected filters</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Credit Issuance Trend -->
                <div>
                    <div class="flex items-center justify-between px-6 py-4">
                        <div>
                            <h2 class="text-base font-semibold text-foreground inline-flex items-center gap-1.5">Credit Issuance <InfoTooltip text="Monthly credit issuance volume derived from project creation dates. Each bar represents total credits (millions tCO2e) for that month." /></h2>
                            <p class="text-xs text-muted-foreground mt-0.5">Monthly volume (millions tCO2e)</p>
                        </div>
                        <NuxtLink to="/analytics" class="text-xs font-medium text-primary hover:underline">Analytics</NuxtLink>
                    </div>
                    <div class="px-6 pb-6">
                        <div class="rounded-xl border bg-card p-5">
                            <!-- Simple bar chart with CSS -->
                            <div v-if="issuanceMonths.length > 0" class="flex items-end gap-3 h-48">
                                <div
                                    v-for="m in issuanceMonths"
                                    :key="m.month"
                                    class="flex-1 flex flex-col items-center gap-2"
                                >
                                    <span class="text-[11px] font-medium text-muted-foreground tabular-nums">{{ m.value }}M</span>
                                    <div
                                        class="w-full rounded-t-md bg-primary/80 hover:bg-primary transition-colors"
                                        :style="{ height: `${(m.value / issuanceMax) * 140}px` }"
                                    />
                                    <span class="text-[11px] text-muted-foreground">{{ m.month }}</span>
                                </div>
                            </div>
                            <div v-else class="flex items-center justify-center h-48 text-sm text-muted-foreground">
                                No issuance data matches the selected filters
                            </div>
                            <div class="flex items-center justify-between mt-4 pt-3 border-t">
                                <span class="text-xs text-muted-foreground">{{ issuanceMonths.length > 0 ? `${issuanceMonths.length}-month total` : 'Total' }}</span>
                                <span class="text-sm font-semibold text-foreground">{{ issuanceTotal }}M tCO2e</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Network Activity (moved to bottom) -->
        <div class="border-t">
            <div class="px-6 py-4">
                <h2 class="text-base font-semibold text-foreground inline-flex items-center gap-1.5">Network Activity <InfoTooltip text="Recent events on the Guardian network including new project registrations, credit issuances, policy publications, and verifications." /></h2>
                <p class="text-xs text-muted-foreground mt-0.5">Recent changes across the Guardian network</p>
            </div>
            <div class="px-6 pb-6">
                <div v-if="recentActivity.length > 0" class="rounded-xl border bg-card divide-y">
                    <div
                        v-for="(item, idx) in recentActivity"
                        :key="idx"
                        class="flex items-center gap-4 px-4 py-3"
                    >
                        <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted">
                            <component :is="activityIcons[item.type]" :class="[activityColors[item.type], 'h-4 w-4']" />
                        </div>
                        <div class="flex-1 min-w-0">
                            <p class="text-sm font-medium text-foreground">{{ item.action }}</p>
                            <p class="text-xs text-muted-foreground truncate">{{ item.detail }}</p>
                        </div>
                        <div class="flex items-center gap-1 shrink-0">
                            <Clock class="h-3 w-3 text-muted-foreground/50" />
                            <span class="text-[11px] text-muted-foreground/70">{{ item.time }}</span>
                        </div>
                    </div>
                </div>
                <div v-else class="rounded-xl border bg-card py-8 text-center text-sm text-muted-foreground">
                    No recent activity matches the selected filters
                </div>
            </div>
        </div>
    </div>
</template>

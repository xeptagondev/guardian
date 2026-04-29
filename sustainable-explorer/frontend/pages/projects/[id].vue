<script setup lang="ts">
import {
    ArrowLeft, FileJson, MapPin, Building2, Coins, FolderKanban,
    Globe, ExternalLink, Info, Database, Calendar, BookOpen, Layers,
} from 'lucide-vue-next';
import { useProjectApi } from '~/composables/api/useProjectApi';

const route = useRoute();
const { network } = useNetwork();
const id = computed(() => route.params.id as string);

const { data: project, pending, notFound } = useProjectApi({ id, network });

const vcViewerOpen = ref(false);

function dash(v: unknown): string {
    if (v === null || v === undefined || v === '') return '—';
    return String(v);
}

const hasCoords = computed(() =>
    !!project.value && project.value.latitude !== null && project.value.longitude !== null,
);

interface LatLng { lat: number; lng: number; }

/**
 * Try to extract a polygon (or multi-point trace) from the source VC.
 * Looks at `coordinates` arrays at the top of credentialSubject and one
 * level into common nested shapes (`location.coordinates`, `geometry.coordinates`).
 */
const polygon = computed<LatLng[] | null>(() => {
    const vc = project.value?.rawVc as Record<string, unknown> | undefined;
    if (!vc) return null;

    const csRaw = vc.credentialSubject;
    const cs: Record<string, unknown> | null = Array.isArray(csRaw)
        ? (csRaw.find((x) => x && typeof x === 'object' && !Array.isArray(x)) as Record<string, unknown> | undefined) ?? null
        : (csRaw && typeof csRaw === 'object' ? (csRaw as Record<string, unknown>) : null);
    if (!cs) return null;

    const candidates: unknown[] = [
        cs.coordinates,
        cs.geometry,
        (cs.location as Record<string, unknown> | undefined)?.coordinates,
        (cs.geometry as Record<string, unknown> | undefined)?.coordinates,
    ];

    for (const c of candidates) {
        if (!Array.isArray(c) || c.length === 0) continue;
        const points = c
            .map((entry): LatLng | null => {
                if (!entry || typeof entry !== 'object') return null;
                const e = entry as Record<string, unknown>;
                const lat = parseFloat(String(e.latitude ?? e.lat ?? ''));
                const lng = parseFloat(String(e.longitude ?? e.lng ?? e.lon ?? ''));
                return Number.isFinite(lat) && Number.isFinite(lng) ? { lat, lng } : null;
            })
            .filter((p): p is LatLng => p !== null);
        if (points.length > 0) return points;
    }
    return null;
});

const hasMapData = computed(() => hasCoords.value || (polygon.value?.length ?? 0) >= 1);

const mapPointSummary = computed(() => {
    const n = polygon.value?.length ?? 0;
    if (n >= 3) return `${n} boundary points`;
    if (n === 2) return '2 points';
    if (n === 1) return '1 point';
    if (hasCoords.value) return '1 point';
    return null;
});

const statusColor: Record<string, { bg: string; text: string; dot: string }> = {
    Registered:        { bg: 'bg-slate-50',   text: 'text-slate-600',   dot: 'bg-slate-400' },
    'Under Validation':{ bg: 'bg-amber-50',   text: 'text-amber-700',   dot: 'bg-amber-500' },
    Verified:          { bg: 'bg-blue-50',    text: 'text-blue-700',    dot: 'bg-blue-500'  },
    Issuing:           { bg: 'bg-emerald-50', text: 'text-emerald-700', dot: 'bg-emerald-500' },
    Approved:          { bg: 'bg-emerald-50', text: 'text-emerald-700', dot: 'bg-emerald-500' },
    Completed:         { bg: 'bg-purple-50',  text: 'text-purple-600',  dot: 'bg-purple-500' },
};
const statusDotClass = (s: string | null) => statusColor[s ?? '']?.dot ?? 'bg-muted-foreground';

const hashscanUrl = computed(() => {
    if (!project.value?.consensusTimestamp) return null;
    return `https://hashscan.io/${network.value === 'mainnet' ? 'mainnet' : 'testnet'}/transaction/${project.value.consensusTimestamp}`;
});

// Backlink to the methodology this project belongs to
const methodologyLink = computed(() => {
    if (!project.value?.instanceTopicId) return null;
    return `/methodologies/${project.value.instanceTopicId}`;
});

const extraEntries = computed(() => {
    const e = project.value?.extras;
    if (!e || typeof e !== 'object') return [] as Array<[string, unknown]>;
    return Object.entries(e);
});
</script>

<template>
    <div v-if="pending" class="p-6 text-sm text-muted-foreground">Loading project…</div>

    <div v-else-if="notFound || !project" class="p-6">
        <div class="rounded-xl border bg-card p-6 text-center">
            <h1 class="text-lg font-semibold text-foreground mb-2">Project not found</h1>
            <p class="text-sm text-muted-foreground">
                No project with ID <code class="font-mono">{{ id }}</code> on <span class="capitalize">{{ network }}</span>.
            </p>
            <NuxtLink to="/methodologies" class="inline-block mt-4 text-sm text-primary hover:underline">
                <ArrowLeft class="h-4 w-4 inline -mt-0.5" /> Back to methodologies
            </NuxtLink>
        </div>
    </div>

    <div v-else class="space-y-6 p-6">
        <!-- Header -->
        <div>
            <NuxtLink
                v-if="methodologyLink"
                :to="methodologyLink"
                class="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground mb-2"
            >
                <ArrowLeft class="h-3.5 w-3.5" />
                Back to methodology
            </NuxtLink>
            <div class="flex items-start justify-between gap-4">
                <div class="min-w-0">
                    <h1 class="text-2xl font-bold text-foreground break-words">{{ project.name || project.projectId || `Project #${project.id}` }}</h1>
                    <p class="text-sm text-muted-foreground mt-1 flex items-center flex-wrap gap-1">
                        <CountryFlag v-if="project.countryCode" :code="project.countryCode" size="sm" class="mr-0.5" />
                        <span>{{ dash(project.country) }}</span>
                        <template v-if="project.proponentName"><span class="mx-1">·</span><span>{{ project.proponentName }}</span></template>
                        <template v-if="project.methodologyTag"><span class="mx-1">·</span><span class="font-mono text-xs">{{ project.methodologyTag }}</span></template>
                    </p>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                    <a
                        v-if="hashscanUrl"
                        :href="hashscanUrl"
                        target="_blank"
                        rel="noopener noreferrer"
                        class="inline-flex items-center gap-2 rounded-lg border bg-card px-4 py-2 text-sm font-medium text-foreground hover:bg-muted transition-colors"
                    >
                        <ExternalLink class="h-4 w-4 text-primary" />
                        View on HashScan
                    </a>
                    <button
                        class="inline-flex items-center gap-2 rounded-lg border bg-card px-4 py-2 text-sm font-medium text-foreground hover:bg-muted transition-colors"
                        @click="vcViewerOpen = true"
                    >
                        <FileJson class="h-4 w-4 text-primary" />
                        View Raw VC
                    </button>
                </div>
            </div>
        </div>

        <!-- Project Details Card -->
        <div class="rounded-xl border bg-card overflow-hidden">
            <div class="px-5 py-3.5 border-b bg-muted/30">
                <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
                    <FolderKanban class="h-4 w-4 text-primary" />
                    Project Details
                </h2>
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-px bg-border">
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Project ID</div>
                    <div class="text-sm font-medium text-foreground break-words">{{ dash(project.projectId) }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Country</div>
                    <div class="text-sm font-medium text-foreground flex items-center gap-1.5">
                        <CountryFlag v-if="project.countryCode" :code="project.countryCode" size="sm" />
                        <span>{{ dash(project.country) }}</span>
                    </div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Region</div>
                    <div class="text-sm font-medium text-foreground">{{ dash(project.region) }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Status</div>
                    <div class="flex items-center gap-2">
                        <span :class="[statusDotClass(project.status), 'h-2 w-2 rounded-full']" />
                        <span class="text-sm font-medium text-foreground">{{ dash(project.status) }}</span>
                    </div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Developer</div>
                    <div class="text-sm font-medium text-foreground">{{ dash(project.proponentName) }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Methodology</div>
                    <div class="text-sm font-medium text-foreground">{{ dash(project.methodologyTag) }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Sector</div>
                    <div class="text-sm font-medium text-foreground">{{ dash(project.sector) }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Project Type</div>
                    <div class="text-sm font-medium text-foreground">{{ dash(project.projectType) }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Category</div>
                    <div class="text-sm font-medium text-foreground">{{ dash(project.category) }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Crediting Period Start</div>
                    <div class="text-sm font-medium text-foreground">{{ dash(project.startDate) }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Crediting Period End</div>
                    <div class="text-sm font-medium text-foreground">{{ dash(project.endDate) }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Vintage</div>
                    <div class="text-sm font-medium text-foreground">{{ dash(project.vintage) }}</div>
                </div>
            </div>

            <div v-if="project.description" class="border-t px-5 py-4">
                <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Description</div>
                <p class="text-sm text-foreground break-words">{{ project.description }}</p>
            </div>
        </div>

        <!-- Location Map (when we have any geo data) -->
        <div v-if="hasMapData" class="rounded-xl border bg-card overflow-hidden">
            <div class="px-5 py-3.5 border-b bg-muted/30">
                <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
                    <MapPin class="h-4 w-4 text-primary" />
                    Project Location
                </h2>
                <p class="text-[11px] text-muted-foreground mt-0.5">
                    <template v-if="mapPointSummary">{{ mapPointSummary }}</template>
                    <template v-if="hasCoords"> · {{ project.latitude!.toFixed(4) }}, {{ project.longitude!.toFixed(4) }}</template>
                    <template v-if="project.country"> · {{ project.country }}</template>
                    <template v-if="project.region"> · {{ project.region }}</template>
                </p>
            </div>
            <div class="h-[420px]">
                <ClientOnly>
                    <ProjectLocationMap
                        :lat="project.latitude"
                        :lng="project.longitude"
                        :polygon="polygon"
                        :name="project.name || project.projectId || 'Project'"
                    />
                </ClientOnly>
            </div>
        </div>

        <div v-else class="rounded-xl border bg-card overflow-hidden">
            <div class="px-5 py-3.5 border-b bg-muted/30">
                <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
                    <MapPin class="h-4 w-4 text-primary" />
                    Project Location
                </h2>
            </div>
            <div class="px-5 py-8 text-center text-sm text-muted-foreground">
                No coordinates extracted for this project.
            </div>
        </div>

        <!-- Extras (everything we couldn't map cleanly) -->
        <div v-if="extraEntries.length > 0" class="rounded-xl border bg-card overflow-hidden">
            <details>
                <summary class="px-5 py-3.5 border-b bg-muted/30 cursor-pointer">
                    <h2 class="text-sm font-semibold text-foreground inline-flex items-center gap-2">
                        <Layers class="h-4 w-4 text-primary" />
                        Additional Fields ({{ extraEntries.length }})
                    </h2>
                    <p class="text-[11px] text-muted-foreground mt-0.5">
                        VC fields not covered by the canonical schema, and language variants.
                    </p>
                </summary>
                <pre class="px-5 py-4 text-[11px] font-mono whitespace-pre-wrap break-words bg-muted/10 max-h-[400px] overflow-auto">{{ JSON.stringify(project.extras, null, 2) }}</pre>
            </details>
        </div>

        <!-- Provenance -->
        <div class="rounded-xl border bg-card overflow-hidden">
            <div class="px-5 py-3 border-b bg-muted/30">
                <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
                    <Database class="h-4 w-4 text-primary" />
                    On-Chain Provenance
                </h2>
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-px bg-border">
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Consensus Timestamp</div>
                    <code class="text-xs font-mono text-foreground">{{ project.consensusTimestamp }}</code>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Schema</div>
                    <code class="text-xs font-mono text-muted-foreground break-all">{{ project.schemaIri }}</code>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Owning Topic</div>
                    <code class="text-xs font-mono text-foreground">{{ project.dynamicTopicId }}</code>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Methodology Topic</div>
                    <code class="text-xs font-mono text-foreground">{{ project.methodologyTopicId }}</code>
                </div>
            </div>
            <div v-if="project.extractionMeta && Object.keys(project.extractionMeta).length > 0" class="border-t px-5 py-3 text-[11px] text-muted-foreground flex items-start gap-2">
                <Info class="h-3.5 w-3.5 mt-0.5 shrink-0" />
                <span>
                    Extracted via
                    <span class="font-mono">{{ (project.extractionMeta as any).identifierName ?? '?' }}</span>
                    identifier and
                    <span class="font-mono">{{ (project.extractionMeta as any).matcherName ?? '?' }}</span>
                    matcher · confidence
                    <span class="font-mono">{{ (project.extractionMeta as any).identifierConfidence ?? '?' }}</span>
                </span>
            </div>
        </div>

        <!-- Linked issuances / lifecycle / SDGs not yet extracted from on-chain VCs -->
        <div class="rounded-xl border border-dashed bg-muted/20 px-5 py-6 text-sm text-muted-foreground space-y-1">
            <div class="font-medium text-foreground flex items-center gap-2">
                <Coins class="h-4 w-4" />
                Issuances, transfers, retirements, SDGs
            </div>
            <p>
                Not yet wired up — these come from issuance / MRV VCs which the indexer doesn't classify
                yet. Phase 2: cross-VC enrichment via <code class="font-mono">presetSchema</code>.
            </p>
        </div>

        <!-- Raw VC viewer modal -->
        <VcJsonViewer
            v-if="vcViewerOpen"
            :open="vcViewerOpen"
            :title="project.name || project.projectId || 'Project VC'"
            :data="project.rawVc ?? null"
            @close="vcViewerOpen = false"
        />
    </div>
</template>

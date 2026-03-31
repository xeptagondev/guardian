<script setup lang="ts">
import {
    ArrowLeft, FileJson, MapPin, Calendar, Building2, Shield, Coins,
    ChevronDown, ChevronUp, Copy, Check, Users, BookOpen, Target,
    Globe, Leaf, FolderKanban, Layers, BarChart3, Clock, Activity,
    GitBranch, ArrowRight, CheckCircle2, Circle, Zap, FileText, Network,
    TrendingUp, TrendingDown, AlertTriangle, Database, ExternalLink,
} from 'lucide-vue-next';
import { MOCK_PROJECTS, MOCK_CREDITS } from '~/data';
import { formatCredits, formatNumber } from '~/lib/format';
import { getSDG } from '~/lib/sdgs';
import { generateProjectVc, generateCreditVc } from '~/lib/mock-vc';

const route = useRoute();
const projectId = computed(() => route.params.id as string);
const project = computed(() => MOCK_PROJECTS.find(p => p.id === projectId.value));
const linkedCredits = computed(() => MOCK_CREDITS.filter(c => c.projectId === projectId.value));
const projectVc = computed(() => project.value ? generateProjectVc(project.value) : null);

const vcViewerOpen = ref(false);
const vcViewerTitle = ref('');
const vcViewerData = ref<Record<string, any> | null>(null);

function viewProjectVc() {
    if (!project.value || !projectVc.value) return;
    vcViewerTitle.value = project.value.name;
    vcViewerData.value = projectVc.value;
    vcViewerOpen.value = true;
}

function viewCreditVc(c: typeof MOCK_CREDITS[number]) {
    vcViewerTitle.value = c.name;
    vcViewerData.value = generateCreditVc(c, project.value?.name);
    vcViewerOpen.value = true;
}

const statusColor: Record<string, { bg: string; text: string; dot: string }> = {
    Active: { bg: 'bg-emerald-50', text: 'text-emerald-700', dot: 'bg-emerald-500' },
    Verified: { bg: 'bg-emerald-50', text: 'text-emerald-700', dot: 'bg-emerald-500' },
    Validated: { bg: 'bg-blue-50', text: 'text-blue-700', dot: 'bg-blue-500' },
    Verification: { bg: 'bg-amber-50', text: 'text-amber-700', dot: 'bg-amber-500' },
    Monitoring: { bg: 'bg-sky-50', text: 'text-sky-700', dot: 'bg-sky-500' },
};

const creditingPeriodStart = computed(() => {
    if (!project.value) return '';
    return `${parseInt(project.value.vintage) - 1}-01-01`;
});

const creditingPeriodEnd = computed(() => {
    if (!project.value) return '';
    return `${parseInt(project.value.vintage) + 9}-12-31`;
});

// Mock emission data derived from project credits
const emissions = computed(() => {
    if (!project.value) return null;
    const baseline = project.value.credits * 0.0057;
    const projectEmissions = baseline * 0.15;
    const leakage = baseline * 0.005;
    const baselineEmissionFactor = baseline / (project.value.credits * 0.0000612);
    return {
        baseline: baseline.toFixed(2),
        project: projectEmissions.toFixed(2),
        leakage: leakage.toFixed(2),
        baselineEmissionFactor: baselineEmissionFactor.toFixed(5),
        net: (baseline - projectEmissions - leakage).toFixed(2),
    };
});

// Mock activity log
const activityLog = computed(() => {
    if (!project.value) return [];
    const base = new Date(project.value.createdAt);
    return [
        { date: new Date(base.getTime() - 180 * 86400000).toISOString().split('T')[0], action: 'Project Design Document submitted', type: 'document' },
        { date: new Date(base.getTime() - 120 * 86400000).toISOString().split('T')[0], action: 'Validation audit initiated', type: 'verification' },
        { date: new Date(base.getTime() - 60 * 86400000).toISOString().split('T')[0], action: 'Validation report approved', type: 'verification' },
        { date: project.value.createdAt, action: 'Project registered on Guardian', type: 'registry' },
        { date: new Date(base.getTime() + 30 * 86400000).toISOString().split('T')[0], action: 'First monitoring period started', type: 'monitoring' },
        { date: new Date(base.getTime() + 180 * 86400000).toISOString().split('T')[0], action: 'Verification report submitted', type: 'verification' },
        { date: new Date(base.getTime() + 210 * 86400000).toISOString().split('T')[0], action: 'Credits issued to Hedera token', type: 'credit' },
    ];
});

const activityTypeIcon: Record<string, { icon: any; color: string }> = {
    document: { icon: FileText, color: 'text-muted-foreground bg-muted' },
    verification: { icon: Shield, color: 'text-amber-600 bg-amber-50' },
    registry: { icon: Database, color: 'text-primary bg-primary/10' },
    monitoring: { icon: Activity, color: 'text-sky-600 bg-sky-50' },
    credit: { icon: Coins, color: 'text-emerald-600 bg-emerald-50' },
};

// Methodology workflow steps
const methodologySteps = computed(() => {
    if (!project.value) return [];
    return [
        { label: 'Project Design', desc: 'PDD submission & stakeholder consultation', status: 'complete' },
        { label: 'Validation', desc: 'Third-party validation audit', status: 'complete' },
        { label: 'Registration', desc: 'Project registration on registry', status: 'complete' },
        { label: 'Monitoring', desc: 'Data collection & MRV reporting', status: project.value.status === 'Monitoring' ? 'active' : 'complete' },
        { label: 'Verification', desc: 'Emission reduction verification', status: project.value.status === 'Verification' ? 'active' : (project.value.status === 'Monitoring' ? 'pending' : 'complete') },
        { label: 'Issuance', desc: 'Credit minting to Hedera token', status: project.value.status === 'Active' ? 'complete' : 'pending' },
    ];
});

const methodologyNameOverrides: Record<string, string> = {
    'vm0007': 'VM0007 — REDD+ Methodology',
    'vm0033': 'VM0033 — Tidal Wetland and Seagrass',
    'vm0044': 'VM0044 — Biochar',
    'vm0036': 'VM0036 — Peatland Rewetting',
    'acm0002': 'ACM0002 — Grid Connected RE',
    'acm0001': 'ACM0001 — Landfill Gas',
    'acm0006': 'ACM0006 — Biomass Energy',
    'ar-acm0003': 'AR-ACM0003 — Reforestation',
    'gs-cookstove': 'GS Cookstove Methodology',
    'gs-sdw': 'GS Safe Drinking Water v1.0',
    'gs-clean-energy': 'GS Clean Energy Methodology',
};

// Generate a deterministic mock transaction timestamp from project creation date
const hashscanUrl = computed(() => {
    if (!project.value) return '';
    const d = new Date(project.value.createdAt);
    const seconds = Math.floor(d.getTime() / 1000);
    const nanos = parseInt(project.value.id) * 32210979;
    return `https://hashscan.io/mainnet/transaction/${seconds}.${String(nanos).padStart(9, '0')}`;
});

const fullMethodologyName = computed(() => {
    if (!project.value) return '';
    return methodologyNameOverrides[project.value.methodologyId] || project.value.methodology;
});
</script>

<template>
    <div v-if="!project" class="p-6">
        <h1 class="text-xl font-bold text-foreground">Project not found</h1>
    </div>

    <div v-else class="space-y-6 p-6">
        <!-- Header -->
        <div>
            <div class="flex items-start justify-between gap-4">
                <div class="min-w-0">
                    <h1 class="text-2xl font-bold text-foreground">{{ project.name }}</h1>
                    <p class="text-sm text-muted-foreground mt-1">
                        {{ project.flag }} {{ project.country }} &middot; {{ project.registry }} &middot; {{ project.developer }}
                    </p>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                    <a
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
                        @click="viewProjectVc"
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
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Project Name</div>
                    <div class="text-sm font-medium text-foreground">{{ project.name }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Country</div>
                    <div class="text-sm font-medium text-foreground">{{ project.flag }} {{ project.country }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Status</div>
                    <div class="flex items-center gap-2">
                        <span :class="[statusColor[project.status]?.dot || 'bg-muted-foreground', 'h-2 w-2 rounded-full']" />
                        <span class="text-sm font-medium text-foreground">{{ project.status }}</span>
                    </div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Methodology</div>
                    <div class="text-sm font-medium text-foreground">{{ fullMethodologyName }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Registry</div>
                    <div class="text-sm font-medium text-foreground">{{ project.registry }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Developer</div>
                    <div class="text-sm font-medium text-foreground">{{ project.developer }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Sector</div>
                    <div class="text-sm font-medium text-foreground">{{ project.sector }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Sectoral Scope</div>
                    <div class="text-sm font-medium text-foreground">{{ project.sectoralScope }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Category</div>
                    <div class="text-sm font-medium text-foreground">{{ project.category }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Crediting Period Start</div>
                    <div class="text-sm font-medium text-foreground">{{ creditingPeriodStart }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Crediting Period End</div>
                    <div class="text-sm font-medium text-foreground">{{ creditingPeriodEnd }}</div>
                </div>
                <div class="bg-card px-5 py-4">
                    <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Projected Emission Reductions</div>
                    <div class="text-sm font-medium text-foreground">{{ formatNumber(project.credits) }} tCO2e</div>
                </div>
            </div>
        </div>

        <!-- Linked Credits -->
        <div class="rounded-xl border bg-card overflow-hidden">
            <div class="px-5 py-3.5 border-b bg-muted/30 flex items-center justify-between">
                <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
                    <Coins class="h-4 w-4 text-primary" />
                    Linked Credits
                </h2>
                <span class="text-xs text-muted-foreground">{{ linkedCredits.length }} credit(s)</span>
            </div>
            <div v-if="linkedCredits.length > 0">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b bg-muted/20">
                            <th class="text-left py-2.5 px-5 text-xs font-medium text-muted-foreground uppercase tracking-wider">Token</th>
                            <th class="text-left py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">Token ID</th>
                            <th class="text-left py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">Type</th>
                            <th class="text-right py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">Supply</th>
                            <th class="text-left py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">Mint Date</th>
                            <th class="text-center py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">VC</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y">
                        <tr v-for="c in linkedCredits" :key="c.id" class="hover:bg-muted/30 transition-colors">
                            <td class="py-3 px-5">
                                <div class="font-medium text-foreground">{{ c.name }}</div>
                                <div class="text-[11px] text-muted-foreground">{{ c.symbol }}</div>
                            </td>
                            <td class="py-3 px-4">
                                <code class="text-xs bg-muted rounded px-1.5 py-0.5 font-mono">{{ c.tokenId }}</code>
                            </td>
                            <td class="py-3 px-4">
                                <span :class="[c.type === 'Fungible' ? 'bg-primary/10 text-primary' : 'bg-chart-4/10 text-chart-4', 'text-xs font-medium rounded-full px-2 py-0.5']">
                                    {{ c.type }}
                                </span>
                            </td>
                            <td class="py-3 px-4 text-right tabular-nums font-medium">{{ formatNumber(c.supply) }}</td>
                            <td class="py-3 px-4 text-muted-foreground">{{ c.mintDate }}</td>
                            <td class="py-3 px-4 text-center">
                                <button
                                    class="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                                    title="View credit VC"
                                    @click="viewCreditVc(c)"
                                >
                                    <FileJson class="h-3.5 w-3.5" />
                                </button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div v-else class="px-5 py-8 text-center text-sm text-muted-foreground">
                No credits have been issued for this project yet.
            </div>
        </div>

        <!-- Emission Parameters Card -->
        <div class="rounded-xl border bg-card overflow-hidden">
            <div class="px-5 py-3.5 border-b bg-muted/30">
                <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
                    <BarChart3 class="h-4 w-4 text-primary" />
                    Emission Parameters
                </h2>
            </div>
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-px bg-border" v-if="emissions">
                <div class="bg-card px-5 py-5">
                    <div class="flex items-center gap-2 mb-2">
                        <div class="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-50">
                            <TrendingUp class="h-4 w-4 text-amber-600" />
                        </div>
                        <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Baseline Emissions</div>
                    </div>
                    <div class="text-lg font-semibold text-foreground tabular-nums">{{ emissions.baseline }}</div>
                    <div class="text-[11px] text-muted-foreground">tCO2e</div>
                </div>
                <div class="bg-card px-5 py-5">
                    <div class="flex items-center gap-2 mb-2">
                        <div class="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-50">
                            <TrendingDown class="h-4 w-4 text-sky-600" />
                        </div>
                        <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Project Emissions</div>
                    </div>
                    <div class="text-lg font-semibold text-foreground tabular-nums">{{ emissions.project }}</div>
                    <div class="text-[11px] text-muted-foreground">tCO2e</div>
                </div>
                <div class="bg-card px-5 py-5">
                    <div class="flex items-center gap-2 mb-2">
                        <div class="flex h-8 w-8 items-center justify-center rounded-lg bg-rose-50">
                            <AlertTriangle class="h-4 w-4 text-rose-500" />
                        </div>
                        <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Leakage Emissions</div>
                    </div>
                    <div class="text-lg font-semibold text-foreground tabular-nums">{{ emissions.leakage }}</div>
                    <div class="text-[11px] text-muted-foreground">tCO2e</div>
                </div>
                <div class="bg-card px-5 py-5">
                    <div class="flex items-center gap-2 mb-2">
                        <div class="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-50">
                            <Target class="h-4 w-4 text-emerald-600" />
                        </div>
                        <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Baseline Emission Factor</div>
                    </div>
                    <div class="text-lg font-semibold text-foreground tabular-nums">{{ emissions.baselineEmissionFactor }}</div>
                    <div class="text-[11px] text-muted-foreground">tCO2e/unit</div>
                </div>
            </div>
        </div>

        <!-- Location Map -->
        <div class="rounded-xl border bg-card overflow-hidden">
            <div class="px-5 py-3.5 border-b bg-muted/30">
                <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
                    <MapPin class="h-4 w-4 text-primary" />
                    Project Location
                </h2>
                <p class="text-[11px] text-muted-foreground mt-0.5">
                    {{ project.lat.toFixed(4) }}, {{ project.lng.toFixed(4) }} &middot; {{ project.country }}
                </p>
            </div>
            <div class="h-[320px]">
                <ClientOnly>
                    <ProjectLocationMap :lat="project.lat" :lng="project.lng" :name="project.name" />
                </ClientOnly>
            </div>
        </div>

        <!-- SDG Icons -->
        <div class="rounded-xl border bg-card overflow-hidden">
            <div class="px-5 py-3.5 border-b bg-muted/30">
                <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
                    <Globe class="h-4 w-4 text-primary" />
                    Sustainable Development Goals
                </h2>
            </div>
            <div class="px-5 py-5">
                <div class="flex flex-wrap gap-3">
                    <div
                        v-for="sdgId in project.sdgs"
                        :key="sdgId"
                        class="group relative flex items-center gap-3 rounded-lg border px-4 py-3 hover:bg-muted/30 transition-colors"
                    >
                        <img
                            :src="`/sdgs/E-WEB-Goal-${String(sdgId).padStart(2, '0')}.png`"
                            :alt="`SDG ${sdgId}`"
                            class="h-10 w-10 rounded"
                        />
                        <div>
                            <div class="text-xs font-semibold text-foreground">SDG {{ sdgId }}</div>
                            <div class="text-[11px] text-muted-foreground">{{ getSDG(sdgId)?.name }}</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Relationships Diagram -->
        <div class="rounded-xl border bg-card overflow-hidden">
            <div class="px-5 py-3.5 border-b bg-muted/30">
                <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
                    <Network class="h-4 w-4 text-primary" />
                    Relationships
                </h2>
                <p class="text-[11px] text-muted-foreground mt-0.5">Entity relationships between Registry, Policy, Schema, Role, VC, VP, and Token</p>
            </div>
            <div class="px-5 py-5">
                <ClientOnly>
                    <RelationshipDiagram
                        :project-name="project.name"
                        :methodology="project.methodology"
                        :methodology-id="project.methodologyId"
                        :registry="project.registry"
                        :developer="project.developer"
                        :project-id="project.id"
                        :vintage="project.vintage"
                        :country="project.country"
                        :sector="project.sector"
                        :token-symbol="linkedCredits[0]?.symbol"
                        :token-name="linkedCredits[0]?.name"
                        :token-id="linkedCredits[0]?.tokenId"
                        @view-vc="({ title, vc }) => { vcViewerTitle = title; vcViewerData = vc; vcViewerOpen = true; }"
                    />
                </ClientOnly>
            </div>
        </div>

        <!-- Activity Log -->
        <div class="rounded-xl border bg-card overflow-hidden">
            <div class="px-5 py-3.5 border-b bg-muted/30">
                <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
                    <Clock class="h-4 w-4 text-primary" />
                    Activity Log
                </h2>
            </div>
            <div class="px-5 py-5">
                <div class="relative">
                    <!-- Timeline line -->
                    <div class="absolute left-[15px] top-3 bottom-3 w-px bg-border" />

                    <div
                        v-for="(event, idx) in activityLog"
                        :key="idx"
                        class="relative flex items-start gap-4 pb-5 last:pb-0"
                    >
                        <div :class="[activityTypeIcon[event.type]?.color || 'text-muted-foreground bg-muted', 'relative z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full']">
                            <component :is="activityTypeIcon[event.type]?.icon || Circle" class="h-3.5 w-3.5" />
                        </div>
                        <div class="pt-1">
                            <div class="text-sm text-foreground">{{ event.action }}</div>
                            <div class="text-[11px] text-muted-foreground mt-0.5">{{ event.date }}</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Methodology -->
        <div class="rounded-xl border bg-card overflow-hidden">
            <div class="px-5 py-3.5 border-b bg-muted/30">
                <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
                    <BookOpen class="h-4 w-4 text-primary" />
                    Methodology
                </h2>
                <p class="text-[11px] text-muted-foreground mt-0.5">{{ fullMethodologyName }}</p>
            </div>
            <div class="px-5 py-5">
                <!-- Workflow Diagram -->
                <div class="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-4">Workflow</div>
                <div class="flex items-center gap-0 overflow-x-auto pb-2">
                    <template v-for="(step, idx) in methodologySteps" :key="idx">
                        <div class="flex flex-col items-center min-w-[120px]">
                            <div
                                :class="[
                                    step.status === 'complete' ? 'bg-emerald-50 border-emerald-200' :
                                    step.status === 'active' ? 'bg-primary/10 border-primary/30 ring-2 ring-primary/20' :
                                    'bg-muted/50 border-border',
                                    'flex h-10 w-10 items-center justify-center rounded-full border transition-colors',
                                ]"
                            >
                                <CheckCircle2
                                    v-if="step.status === 'complete'"
                                    class="h-5 w-5 text-emerald-600"
                                />
                                <Zap
                                    v-else-if="step.status === 'active'"
                                    class="h-5 w-5 text-primary"
                                />
                                <Circle
                                    v-else
                                    class="h-5 w-5 text-muted-foreground/40"
                                />
                            </div>
                            <div class="mt-2 text-center">
                                <div
                                    :class="[
                                        step.status === 'active' ? 'text-primary font-semibold' :
                                        step.status === 'complete' ? 'text-foreground font-medium' :
                                        'text-muted-foreground',
                                        'text-xs',
                                    ]"
                                >
                                    {{ step.label }}
                                </div>
                                <div class="text-[10px] text-muted-foreground mt-0.5 max-w-[110px] leading-tight">{{ step.desc }}</div>
                            </div>
                        </div>
                        <div
                            v-if="idx < methodologySteps.length - 1"
                            class="flex-1 min-w-[24px] h-px mt-[-24px]"
                            :class="step.status === 'complete' ? 'bg-emerald-300' : 'bg-border'"
                        />
                    </template>
                </div>
            </div>
        </div>

        <!-- VC Viewer Modal -->
        <VcJsonViewer :open="vcViewerOpen" :title="vcViewerTitle" :data="vcViewerData" @close="vcViewerOpen = false" />
    </div>
</template>

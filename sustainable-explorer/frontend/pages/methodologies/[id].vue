<script setup lang="ts">
import {
  ArrowLeft,
  BookOpen,
  Shield,
  ExternalLink,
  CheckCircle2,
  Clock,
  GitBranch,
  BarChart3,
  Zap,
  Building2,
  Layers,
  ChevronRight,
  FileText,
  Copy,
  Check,
  Hash,
  AlertCircle,
} from "lucide-vue-next";
import { formatCredits } from "~/lib/format";
import type {
  MethodologyDto,
  MethodologiesResponse,
} from "~/composables/api/useMethodologiesApi";
import { usePolicyDetailApi } from "~/composables/api/usePolicyDetailApi";
import { usePolicyProjectsApi } from "~/composables/api/usePolicyProjectsApi";
import PolicyFlowDiagram from "~/components/policy/PolicyFlowDiagram.vue";
import type { PolicyBlock } from "~/types/policy";
import { X, RefreshCw, Workflow, MapPin, Calendar, Search } from "lucide-vue-next";

const route = useRoute();
const { network } = useNetwork();

const id = computed(() => route.params.id as string);

const {
  data: methodology,
  pending,
  error,
} = useMethodologyApi({ id, network });

// Fetch all versions of this policy once the main methodology loads
const policyTopicId = computed(() => methodology.value?.policyTopicId ?? null);

const versions = ref<MethodologyDto[]>([]);
const versionsPending = ref(false);

if (import.meta.client) {
  const config = useRuntimeConfig();
  const baseURL = config.public.apiBaseUrl as string;

  watch(
    policyTopicId,
    async (pid) => {
      if (!pid) return;
      versionsPending.value = true;
      try {
        const res = await $fetch<MethodologiesResponse>(
          `/api/v1/${network.value}/methodologies`,
          {
            baseURL,
            query: {
              policyTopicId: pid,
              sortBy: "sourceTimestamp",
              sortDir: "desc",
              limit: 50,
              page: 1,
            },
          },
        );
        versions.value = res.data ?? [];
      } catch {
        versions.value = [];
      } finally {
        versionsPending.value = false;
      }
    },
    { immediate: true },
  );
}

const activeTab = ref<
  "overview" | "versions" | "projects" | "policy" | "analytics" | "actions"
>("overview");

// Decoded policy (block tree) — fetched lazily when the policy tab opens.
const {
  data: policyDetail,
  pending: policyPending,
  notFound: policyNotFound,
  refresh: refreshPolicy,
} = usePolicyDetailApi({ id, network });

const selectedBlock = ref<PolicyBlock | null>(null);
function onSelectBlock(block: PolicyBlock) {
  selectedBlock.value = block;
}
function clearSelectedBlock() {
  selectedBlock.value = null;
}

// Linked projects (canonical rows extracted from project VCs)
const projectsPage = ref(1);
const projectsLimit = ref(20);
const projectsSearch = ref('');
const {
  data: projectsResponse,
  pending: projectsPending,
  refresh: refreshProjects,
} = usePolicyProjectsApi({
  methodologyId: id,
  network,
  page: projectsPage,
  limit: projectsLimit,
  search: projectsSearch,
});

const projectRows = computed(() => projectsResponse.value?.data ?? []);
const projectsMeta = computed(() => projectsResponse.value?.meta ?? { page: 1, limit: 20, total: 0, totalPages: 1 });


const tabs = [
  { key: "overview", label: "Overview", icon: BookOpen },
  { key: "versions", label: "Version History", icon: Clock },
  { key: "projects", label: "Linked Projects", icon: Layers },
  { key: "policy", label: "Hedera Policy", icon: Shield },
  { key: "analytics", label: "Analytics", icon: BarChart3 },
  { key: "actions", label: "Actions", icon: Zap },
] as const;

const statusBadgeClass = (status: string | null | undefined) => {
  const s = (status ?? "").toUpperCase();
  if (s === "PUBLISHED") return "bg-stat-green/10 text-stat-green";
  if (s === "DRAFT") return "bg-stat-amber/10 text-stat-amber";
  return "bg-muted text-muted-foreground";
};

const copiedValue = ref<string | null>(null);
async function copyValue(val: string) {
  try {
    await navigator.clipboard.writeText(val);
    copiedValue.value = val;
    setTimeout(() => {
      if (copiedValue.value === val) copiedValue.value = null;
    }, 2000);
  } catch {}
}

const hashscanUrl = computed(() =>
  methodology.value?.topicId
    ? `https://hashscan.io/${network.value}/topic/${methodology.value.topicId}`
    : null,
);

const publishedAt = computed(() => {
  const ts = methodology.value?.sourceTimestamp;
  if (!ts) return null;
  return new Date(parseFloat(ts) * 1000).toLocaleString();
});
</script>

<template>
  <div class="space-y-6 p-6">
    <!-- Breadcrumb -->
    <div class="flex items-center gap-2 text-sm text-muted-foreground">
      <NuxtLink
        to="/methodologies"
        class="hover:text-foreground transition-colors flex items-center gap-1"
      >
        <ArrowLeft class="h-3.5 w-3.5" />
        Methodologies
      </NuxtLink>
      <ChevronRight class="h-3.5 w-3.5" />
      <span class="text-foreground font-medium">{{
        methodology?.name ?? id
      }}</span>
    </div>

    <!-- Loading skeleton -->
    <template v-if="pending">
      <div class="space-y-4">
        <Skeleton class="h-10 w-2/3" />
        <Skeleton class="h-4 w-1/2" />
        <Skeleton class="h-24 w-full rounded-xl" />
      </div>
    </template>

    <!-- Error state -->
    <template v-else-if="error || !methodology">
      <div class="rounded-xl border bg-card px-6 py-12 text-center">
        <AlertCircle class="h-8 w-8 text-destructive mx-auto mb-3" />
        <p class="text-sm font-medium text-foreground mb-1">
          Methodology not found
        </p>
        <p class="text-xs text-muted-foreground mb-4">
          No methodology with ID <code class="font-mono">{{ id }}</code> on
          {{ network }}.
        </p>
        <NuxtLink
          to="/methodologies"
          class="text-sm text-primary hover:underline"
          >← Back to Methodologies</NuxtLink
        >
      </div>
    </template>

    <!-- Content -->
    <template v-else>
      <!-- Header -->
      <div class="flex items-start justify-between gap-4">
        <div class="min-w-0">
          <div class="flex items-center gap-3 mb-2">
            <div
              class="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10"
            >
              <BookOpen class="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 class="text-2xl font-bold text-foreground">
                {{ methodology.name }}
              </h1>
              <p class="text-sm text-muted-foreground">
                {{ methodology.registryName || methodology.registryDid || "—" }}
                <template v-if="methodology.version"
                  >&middot; {{ methodology.version }}</template
                >
              </p>
            </div>
          </div>
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
        </div>
      </div>

      <!-- Summary card -->
      <div class="rounded-xl border bg-card overflow-hidden">
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-px bg-border">
          <div class="bg-card px-5 py-4">
            <div
              class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1"
            >
              Registry
            </div>
            <div
              class="text-sm font-medium text-foreground flex items-center gap-1.5"
            >
              <Building2 class="h-3.5 w-3.5 text-muted-foreground shrink-0" />
              <span class="truncate">{{
                methodology.registryName || methodology.registryDid || "—"
              }}</span>
            </div>
          </div>
          <div class="bg-card px-5 py-4">
            <div
              class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1"
            >
              Version
            </div>
            <div class="text-sm font-medium text-foreground">
              <span
                v-if="methodology.version"
                class="font-mono bg-muted rounded px-1.5 py-0.5 text-xs"
                >{{ methodology.version }}</span
              >
              <span v-else class="text-muted-foreground">—</span>
            </div>
          </div>
          <div class="bg-card px-5 py-4">
            <div
              class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1"
            >
              Schemas
            </div>
            <div class="text-sm font-semibold text-foreground tabular-nums">
              {{ methodology.stats.schemaCount }}
            </div>
          </div>
          <div class="bg-card px-5 py-4">
            <div
              class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1"
            >
              Status
            </div>
            <span
              :class="[
                statusBadgeClass(methodology.status),
                'text-xs font-medium rounded-full px-2 py-0.5',
              ]"
            >
              {{ methodology.status ?? "—" }}
            </span>
          </div>
        </div>
      </div>

      <!-- Tab Navigation -->
      <div class="border-b">
        <nav class="flex gap-0 -mb-px overflow-x-auto">
          <button
            v-for="tab in tabs"
            :key="tab.key"
            :class="[
              activeTab === tab.key
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border',
              'flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors whitespace-nowrap',
            ]"
            @click="activeTab = tab.key"
          >
            <component :is="tab.icon" class="h-4 w-4" />
            {{ tab.label }}
          </button>
        </nav>
      </div>

      <!-- Tab: Overview -->
      <div v-if="activeTab === 'overview'" class="space-y-6">
        <div class="rounded-xl border bg-card overflow-hidden">
          <div class="px-5 py-3.5 border-b bg-muted/30">
            <h2
              class="text-sm font-semibold text-foreground flex items-center gap-2"
            >
              <FileText class="h-4 w-4 text-primary" />
              Description
            </h2>
          </div>
          <div class="px-5 py-5">
            <p
              v-if="methodology.description"
              class="text-sm text-foreground leading-relaxed"
            >
              {{ methodology.description }}
            </p>
            <p v-else class="text-sm text-muted-foreground italic">
              No description available.
            </p>
          </div>
        </div>

        <!-- Key Facts -->
        <div class="rounded-xl border bg-card overflow-hidden">
          <div class="px-5 py-3.5 border-b bg-muted/30">
            <h2
              class="text-sm font-semibold text-foreground flex items-center gap-2"
            >
              <Hash class="h-4 w-4 text-primary" />
              Key Facts
            </h2>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-px bg-border">
            <div class="bg-card px-5 py-4">
              <div
                class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1"
              >
                Published At
              </div>
              <div class="text-sm text-foreground">
                {{ publishedAt ?? "—" }}
              </div>
            </div>
            <div class="bg-card px-5 py-4">
              <div
                class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1"
              >
                Network
              </div>
              <div class="text-sm text-foreground capitalize">
                {{ methodology.network }}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab: Version History -->
      <div v-else-if="activeTab === 'versions'" class="space-y-6">
        <div class="rounded-xl border bg-card overflow-hidden">
          <div
            class="px-5 py-3.5 border-b bg-muted/30 flex items-center justify-between"
          >
            <h2
              class="text-sm font-semibold text-foreground flex items-center gap-2"
            >
              <Clock class="h-4 w-4 text-primary" />
              Version History
            </h2>
            <span v-if="!versionsPending" class="text-xs text-muted-foreground">
              {{ versions.length }} version(s)
            </span>
          </div>

          <!-- Loading -->
          <template v-if="versionsPending">
            <div class="divide-y">
              <div v-for="i in 3" :key="i" class="px-5 py-3 flex gap-4">
                <Skeleton class="h-4 w-20" />
                <Skeleton class="h-4 w-32" />
                <Skeleton class="h-4 w-28" />
                <Skeleton class="h-4 w-10 ml-auto" />
              </div>
            </div>
          </template>

          <table v-else class="w-full text-sm">
            <thead>
              <tr class="border-b bg-muted/20">
                <th
                  class="text-left py-2.5 px-5 text-xs font-medium text-muted-foreground uppercase tracking-wider"
                >
                  Version
                </th>
                <th
                  class="text-left py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider"
                >
                  Instance Policy Topic
                </th>
                <th
                  class="text-left py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider"
                >
                  Published
                </th>
                <th
                  class="text-right py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider"
                >
                  Schemas
                </th>
                <th
                  class="text-left py-2.5 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider"
                >
                  Status
                </th>
              </tr>
            </thead>
            <tbody class="divide-y">
              <tr
                v-for="v in versions"
                :key="v.topicId ?? v.id"
                :class="[
                  v.topicId === id ? 'bg-primary/5' : 'hover:bg-muted/30',
                  'transition-colors cursor-pointer',
                ]"
                @click="
                  v.topicId &&
                  v.topicId !== id &&
                  navigateTo('/methodologies/' + v.topicId)
                "
              >
                <td class="py-3 px-5">
                  <div class="flex items-center gap-2">
                    <span
                      v-if="v.version"
                      class="text-xs font-mono bg-muted rounded px-1.5 py-0.5"
                      >{{ v.version }}</span
                    >
                    <span v-else class="text-xs text-muted-foreground">—</span>
                    <span
                      v-if="v.topicId === id"
                      class="text-[10px] font-medium bg-primary/10 text-primary rounded-full px-2 py-0.5"
                      >Current</span
                    >
                  </div>
                </td>
                <td class="py-3 px-4">
                  <div class="group flex items-center gap-2">
                    <code class="text-xs font-mono text-muted-foreground">{{
                      v.topicId ?? "—"
                    }}</code>
                    <button
                      v-if="v.topicId"
                      class="opacity-0 group-hover:opacity-100 transition-opacity flex h-5 w-5 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground"
                      @click.stop="copyValue(v.topicId!)"
                    >
                      <Check
                        v-if="copiedValue === v.topicId"
                        class="h-3 w-3 text-stat-green"
                      />
                      <Copy v-else class="h-3 w-3" />
                    </button>
                  </div>
                </td>
                <td class="py-3 px-4 text-xs text-muted-foreground">
                  {{
                    v.sourceTimestamp
                      ? new Date(
                          parseFloat(v.sourceTimestamp) * 1000,
                        ).toLocaleDateString()
                      : "—"
                  }}
                </td>
                <td
                  class="py-3 px-4 text-right tabular-nums text-sm font-medium"
                >
                  {{ v.stats.schemaCount }}
                </td>
                <td class="py-3 px-4">
                  <span
                    :class="[
                      statusBadgeClass(v.status),
                      'text-xs font-medium rounded-full px-2 py-0.5',
                    ]"
                  >
                    {{ v.status ?? "—" }}
                  </span>
                </td>
              </tr>
              <tr v-if="!versions.length">
                <td
                  colspan="5"
                  class="py-8 text-center text-sm text-muted-foreground"
                >
                  No versions found.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Tab: Linked Projects -->
      <div v-else-if="activeTab === 'projects'" class="space-y-4">
        <div class="rounded-xl border bg-card overflow-hidden">
          <div class="px-5 py-3 border-b bg-muted/30 flex items-center justify-between">
            <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
              <Layers class="h-4 w-4 text-primary" />
              Linked Projects
              <span class="text-xs text-muted-foreground font-normal">
                ({{ projectsMeta.total }} total)
              </span>
            </h2>
            <div class="flex items-center gap-2">
              <div class="relative">
                <Search class="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <input
                  v-model="projectsSearch"
                  type="text"
                  placeholder="Search name, id, description…"
                  class="pl-8 pr-3 py-1.5 text-xs rounded-md border bg-background focus:outline-none focus:ring-1 focus:ring-primary w-64"
                  @input="projectsPage = 1"
                />
              </div>
              <button
                class="text-xs text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
                :disabled="projectsPending"
                @click="refreshProjects()"
              >
                <RefreshCw class="h-3.5 w-3.5" :class="projectsPending ? 'animate-spin' : ''" />
                Refresh
              </button>
            </div>
          </div>

          <div v-if="projectsPending && projectRows.length === 0" class="px-5 py-12 text-center text-sm text-muted-foreground">
            Loading projects…
          </div>

          <div v-else-if="projectRows.length === 0" class="px-5 py-12 text-center text-sm text-muted-foreground space-y-1">
            <Layers class="h-8 w-8 mx-auto mb-2 opacity-30" />
            <p class="font-medium text-foreground">No projects yet</p>
            <p class="max-w-md mx-auto">
              The project extractor hasn't found any project VCs for this
              methodology. This could mean: no projects have been registered yet,
              VCs haven't been fetched from IPFS, or the project schema hasn't
              been resolved. Check the worker logs.
            </p>
          </div>

          <div v-else class="overflow-x-auto">
            <table class="w-full min-w-[900px] text-sm">
              <thead>
                <tr class="border-b bg-muted/20 text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                  <th class="text-left py-2.5 px-4">Project</th>
                  <th class="text-left py-2.5 px-4">Country / Region</th>
                  <th class="text-left py-2.5 px-4">Vintage</th>
                  <th class="text-left py-2.5 px-4">Status</th>
                  <th class="text-left py-2.5 px-4">Period</th>
                  <th class="text-right py-2.5 px-4">Submitted</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="p in projectRows"
                  :key="p.id"
                  class="border-b last:border-b-0 hover:bg-muted/30 cursor-pointer transition-colors"
                  @click="navigateTo(`/projects/${p.id}`)"
                >
                  <td class="py-3 px-4">
                    <div class="font-medium text-foreground break-words max-w-[280px]">
                      {{ p.name || '—' }}
                    </div>
                    <div v-if="p.projectId" class="text-[11px] font-mono text-muted-foreground truncate max-w-[280px]">
                      {{ p.projectId }}
                    </div>
                    <div
                      v-if="p.projectType || p.sector"
                      class="text-[11px] text-muted-foreground truncate max-w-[280px]"
                    >
                      <template v-if="p.projectType">{{ p.projectType }}</template>
                      <template v-if="p.projectType && p.sector"> · </template>
                      <template v-if="p.sector">{{ p.sector }}</template>
                    </div>
                  </td>
                  <td class="py-3 px-4 text-foreground">
                    <div v-if="p.country || p.region" class="flex items-center gap-1.5">
                      <MapPin class="h-3 w-3 text-muted-foreground" />
                      <span>{{ p.country ?? '—' }}<template v-if="p.region">, {{ p.region }}</template></span>
                    </div>
                    <span v-else class="text-muted-foreground">—</span>
                  </td>
                  <td class="py-3 px-4 text-foreground">{{ p.vintage ?? '—' }}</td>
                  <td class="py-3 px-4">
                    <span
                      v-if="p.status"
                      class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-muted text-muted-foreground"
                    >
                      {{ p.status }}
                    </span>
                    <span v-else class="text-muted-foreground">—</span>
                  </td>
                  <td class="py-3 px-4 text-xs text-muted-foreground">
                    <div v-if="p.startDate || p.endDate" class="flex items-center gap-1">
                      <Calendar class="h-3 w-3" />
                      <span>{{ p.startDate ?? '?' }} → {{ p.endDate ?? '?' }}</span>
                    </div>
                    <span v-else>—</span>
                  </td>
                  <td class="py-3 px-4 text-right text-xs text-muted-foreground tabular-nums">
                    {{ new Date(p.createdAt).toLocaleDateString() }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div
            v-if="projectsMeta.totalPages > 1"
            class="px-5 py-3 border-t bg-muted/10 flex items-center justify-between text-xs text-muted-foreground"
          >
            <span>
              Page {{ projectsMeta.page }} of {{ projectsMeta.totalPages }} —
              {{ projectsMeta.total }} project{{ projectsMeta.total === 1 ? '' : 's' }}
            </span>
            <div class="flex items-center gap-1">
              <button
                class="px-2 py-1 rounded hover:bg-muted disabled:opacity-50"
                :disabled="projectsPage <= 1"
                @click="projectsPage = Math.max(1, projectsPage - 1)"
              >
                Prev
              </button>
              <button
                class="px-2 py-1 rounded hover:bg-muted disabled:opacity-50"
                :disabled="projectsPage >= projectsMeta.totalPages"
                @click="projectsPage = Math.min(projectsMeta.totalPages, projectsPage + 1)"
              >
                Next
              </button>
            </div>
          </div>
        </div>

      </div>

      <!-- Tab: Hedera Policy -->
      <div v-else-if="activeTab === 'policy'" class="space-y-4">
        <!-- Metadata strip -->
        <div class="rounded-xl border bg-card overflow-hidden">
          <div class="px-5 py-3 border-b bg-muted/30 flex items-center justify-between">
            <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
              <Shield class="h-4 w-4 text-primary" />
              On-Chain Policy
            </h2>
            <span
              v-if="policyDetail"
              class="text-xs px-2 py-0.5 rounded font-medium"
              :class="policyDetail.status === 'DECODED'
                ? 'bg-stat-green/10 text-stat-green'
                : 'bg-stat-amber/10 text-stat-amber'"
            >
              {{ policyDetail.status }}
            </span>
          </div>
          <div class="px-5 py-4 grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">
                Instance Topic
              </div>
              <div class="group flex items-center gap-2">
                <code class="text-sm font-mono text-foreground">{{ methodology.topicId ?? '—' }}</code>
                <button
                  v-if="methodology.topicId"
                  class="opacity-0 group-hover:opacity-100 transition-opacity flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
                  @click="copyValue(methodology.topicId!)"
                >
                  <Check v-if="copiedValue === methodology.topicId" class="h-3.5 w-3.5 text-stat-green" />
                  <Copy v-else class="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
            <div>
              <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">
                Policy Topic
              </div>
              <div class="group flex items-center gap-2">
                <code class="text-sm font-mono text-foreground">
                  {{ policyDetail?.policyTopicId ?? methodology.policyTopicId ?? '—' }}
                </code>
                <button
                  v-if="policyDetail?.policyTopicId"
                  class="opacity-0 group-hover:opacity-100 transition-opacity flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
                  @click="copyValue(policyDetail.policyTopicId)"
                >
                  <Check v-if="copiedValue === policyDetail.policyTopicId" class="h-3.5 w-3.5 text-stat-green" />
                  <Copy v-else class="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
            <div>
              <div class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">
                Source CID
              </div>
              <div class="group flex items-center gap-2">
                <code
                  class="text-xs font-mono text-muted-foreground truncate max-w-[180px]"
                  :title="policyDetail?.cid ?? ''"
                >{{ policyDetail?.cid ?? '—' }}</code>
                <button
                  v-if="policyDetail?.cid"
                  class="opacity-0 group-hover:opacity-100 transition-opacity flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
                  @click="copyValue(policyDetail.cid!)"
                >
                  <Check v-if="copiedValue === policyDetail.cid" class="h-3.5 w-3.5 text-stat-green" />
                  <Copy v-else class="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          </div>
          <div v-if="hashscanUrl" class="px-5 py-2 border-t bg-muted/10">
            <a
              :href="hashscanUrl"
              target="_blank"
              rel="noopener noreferrer"
              class="inline-flex items-center gap-2 text-xs text-primary hover:underline font-medium"
            >
              <ExternalLink class="h-3.5 w-3.5" />
              View on HashScan
            </a>
          </div>
        </div>

        <!-- Workflow diagram -->
        <div class="rounded-xl border bg-card overflow-hidden">
          <div class="px-5 py-3 border-b bg-muted/30 flex items-center justify-between">
            <h2 class="text-sm font-semibold text-foreground flex items-center gap-2">
              <Workflow class="h-4 w-4 text-primary" />
              Policy Workflow
            </h2>
            <button
              class="text-xs text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
              :disabled="policyPending"
              @click="refreshPolicy()"
            >
              <RefreshCw class="h-3.5 w-3.5" :class="policyPending ? 'animate-spin' : ''" />
              Refresh
            </button>
          </div>
          <div class="relative grid" :class="selectedBlock ? 'lg:grid-cols-[1fr_22rem]' : 'grid-cols-1'">
            <!-- Diagram canvas -->
            <div class="relative h-[640px] bg-gray-50/50">
              <div
                v-if="policyPending"
                class="absolute inset-0 flex items-center justify-center text-sm text-muted-foreground"
              >
                Loading policy…
              </div>
              <div
                v-else-if="policyNotFound || !policyDetail?.config"
                class="absolute inset-0 flex flex-col items-center justify-center gap-3 text-center px-6"
              >
                <AlertCircle class="h-8 w-8 text-muted-foreground/50" />
                <div>
                  <div class="text-sm font-medium text-foreground">
                    Policy archive not yet decoded
                  </div>
                  <div class="text-xs text-muted-foreground mt-1 max-w-md">
                    The Instance-Policy ZIP for this methodology hasn't been
                    fetched and decoded yet. Once the worker processes it, the
                    block tree will appear here.
                  </div>
                </div>
                <button
                  class="inline-flex items-center gap-2 text-sm text-primary hover:underline font-medium"
                  @click="refreshPolicy()"
                >
                  <RefreshCw class="h-3.5 w-3.5" />
                  Check again
                </button>
              </div>
              <PolicyFlowDiagram
                v-else
                :config="policyDetail.config"
                @select-block="onSelectBlock"
              />
            </div>

            <!-- Side panel: selected block details -->
            <div
              v-if="selectedBlock"
              class="border-l bg-card overflow-hidden flex flex-col h-[640px]"
            >
              <div class="px-4 py-3 border-b flex items-center justify-between bg-muted/30">
                <div class="min-w-0">
                  <div class="text-sm font-semibold text-foreground truncate">
                    {{ selectedBlock.tag || selectedBlock.blockType }}
                  </div>
                  <div class="text-[10px] font-mono text-muted-foreground truncate">
                    {{ selectedBlock.blockType }}
                  </div>
                </div>
                <button
                  class="flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
                  @click="clearSelectedBlock"
                >
                  <X class="h-4 w-4" />
                </button>
              </div>
              <div class="flex-1 overflow-auto px-4 py-3">
                <pre class="text-[11px] font-mono text-foreground whitespace-pre-wrap break-words">{{ JSON.stringify(selectedBlock, null, 2) }}</pre>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab: Analytics -->
      <div v-else-if="activeTab === 'analytics'" class="space-y-6">
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div class="rounded-xl border bg-card px-5 py-5">
            <div
              class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-2"
            >
              Schema Count
            </div>
            <div class="text-2xl font-bold text-foreground tabular-nums">
              {{ methodology.stats.schemaCount }}
            </div>
            <div class="text-xs text-muted-foreground mt-1">
              Data forms in this policy
            </div>
          </div>
          <div class="rounded-xl border bg-card px-5 py-5">
            <div
              class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-2"
            >
              Projects
            </div>
            <div class="text-2xl font-bold text-foreground tabular-nums">
              {{ methodology.stats.projectCount }}
            </div>
            <div class="text-xs text-muted-foreground mt-1">
              Registered under this methodology
            </div>
          </div>
          <div class="rounded-xl border bg-card px-5 py-5">
            <div
              class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-2"
            >
              Issuances
            </div>
            <div class="text-2xl font-bold text-foreground tabular-nums">
              {{ formatCredits(methodology.stats.issuanceCount) }}
            </div>
            <div class="text-xs text-muted-foreground mt-1">Credits issued</div>
          </div>
        </div>

        <div class="rounded-xl border bg-card overflow-hidden">
          <div class="px-5 py-3.5 border-b bg-muted/30">
            <h2
              class="text-sm font-semibold text-foreground flex items-center gap-2"
            >
              <BarChart3 class="h-4 w-4 text-primary" />
              Trends
            </h2>
          </div>
          <div class="px-5 py-8 text-center text-sm text-muted-foreground">
            <BarChart3 class="h-8 w-8 mx-auto mb-3 opacity-30" />
            <p>
              Issuance over time, retirement trend, and geography charts will be
              available once live VC-Document data is fully synced.
            </p>
          </div>
        </div>
      </div>

      <!-- Tab: Actions -->
      <div v-else-if="activeTab === 'actions'" class="space-y-6">
        <div class="rounded-xl border bg-card overflow-hidden">
          <div class="px-5 py-3.5 border-b bg-muted/30">
            <h2
              class="text-sm font-semibold text-foreground flex items-center gap-2"
            >
              <Zap class="h-4 w-4 text-primary" />
              Actions
            </h2>
          </div>
          <div class="px-5 py-5 space-y-4">
            <div>
              <h3 class="text-sm font-semibold text-foreground mb-1">
                About this Methodology
              </h3>
              <p class="text-sm text-muted-foreground">
                {{ methodology.description || "No description available." }}
              </p>
              <p class="text-sm text-muted-foreground mt-2">
                Instance Policy Topic:
                <code
                  class="text-xs bg-muted rounded px-1.5 py-0.5 font-mono"
                  >{{ methodology.topicId }}</code
                >
              </p>
            </div>
            <div class="border-t pt-4">
              <h3 class="text-sm font-semibold text-foreground mb-2">
                Compare Methodologies
              </h3>
              <p class="text-sm text-muted-foreground mb-3">
                Select another methodology to compare side-by-side against this
                one.
              </p>
              <button
                disabled
                class="inline-flex items-center gap-2 rounded-lg border bg-muted/30 px-4 py-2 text-sm font-medium text-muted-foreground cursor-not-allowed"
              >
                <GitBranch class="h-4 w-4" />
                Compare (Coming Soon)
              </button>
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

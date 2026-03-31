<script setup lang="ts">
import { Search, FolderKanban, Coins, BookOpen, Building2 } from 'lucide-vue-next';
import { MOCK_PROJECTS, MOCK_CREDITS } from '~/data';
import { formatCredits } from '~/lib/format';

const route = useRoute();
const query = ref((route.query.q as string) || '');

const results = computed(() => {
    const q = query.value.trim().toLowerCase();

    const items: { type: string; icon: any; color: string; title: string; description: string }[] = [];

    // Search projects
    for (const p of MOCK_PROJECTS) {
        if (
            p.name.toLowerCase().includes(q) ||
            p.country.toLowerCase().includes(q) ||
            p.methodology.toLowerCase().includes(q) ||
            p.registry.toLowerCase().includes(q)
        ) {
            items.push({
                type: 'Project',
                icon: FolderKanban,
                color: 'text-stat-amber',
                title: p.name,
                description: `${p.registry} ${p.category.toLowerCase()} project in ${p.country} \u2014 ${formatCredits(p.credits)} tCO2e`,
            });
        }
    }

    // Search credits
    for (const c of MOCK_CREDITS) {
        if (
            c.name.toLowerCase().includes(q) ||
            c.symbol.toLowerCase().includes(q) ||
            c.tokenId.toLowerCase().includes(q)
        ) {
            const project = MOCK_PROJECTS.find(p => p.id === c.projectId);
            items.push({
                type: 'Credit',
                icon: Coins,
                color: 'text-stat-rose',
                title: `${c.name} (${c.symbol})`,
                description: `Token ${c.tokenId} \u2014 ${formatCredits(c.supply)} tCO2e${project ? ` for ${project.name}` : ''}`,
            });
        }
    }

    // Search methodologies (derived from projects)
    const methMap: Record<string, { name: string; registry: string; projects: number }> = {};
    for (const p of MOCK_PROJECTS) {
        if (!methMap[p.methodologyId]) {
            methMap[p.methodologyId] = { name: p.methodology, registry: p.registry, projects: 0 };
        }
        methMap[p.methodologyId].projects++;
    }
    for (const m of Object.values(methMap)) {
        if (m.name.toLowerCase().includes(q)) {
            items.push({
                type: 'Methodology',
                icon: BookOpen,
                color: 'text-stat-green',
                title: m.name,
                description: `${m.registry} methodology \u2014 ${m.projects} projects`,
            });
        }
    }

    // Search registries (derived from projects)
    const regMap: Record<string, { policies: number; projects: number }> = {};
    for (const p of MOCK_PROJECTS) {
        if (!regMap[p.registry]) regMap[p.registry] = { policies: 0, projects: 0 };
        regMap[p.registry].projects++;
    }
    for (const [name, data] of Object.entries(regMap)) {
        if (name.toLowerCase().includes(q)) {
            items.push({
                type: 'Registry',
                icon: Building2,
                color: 'text-stat-blue',
                title: name,
                description: `Standard Registry \u2014 ${data.projects} projects`,
            });
        }
    }

    return q.length > 0 ? items.slice(0, 20) : items.slice(0, 5);
});

const typeColor: Record<string, string> = {
    Project: 'bg-stat-amber/10 text-stat-amber',
    Credit: 'bg-stat-rose/10 text-stat-rose',
    Methodology: 'bg-stat-green/10 text-stat-green',
    Registry: 'bg-stat-blue/10 text-stat-blue',
};
</script>

<template>
    <div class="space-y-0">
        <div class="px-6 pt-6 pb-5">
            <h1 class="text-2xl font-bold text-foreground">Search</h1>
            <p class="text-sm text-muted-foreground mt-1">Find projects, credits, methodologies, and registries</p>
        </div>

        <div class="px-6 pb-4">
            <div class="relative">
                <Search class="absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input v-model="query" placeholder="Search by name, DID, token ID, or keyword..." class="pl-10 h-11 text-base" />
            </div>
        </div>

        <div class="px-6 pb-6">
            <div class="rounded-xl border bg-card divide-y">
                <div
                    v-for="(r, idx) in results"
                    :key="idx"
                    class="flex items-center gap-4 px-4 py-3.5 hover:bg-muted/30 transition-colors cursor-pointer"
                >
                    <div :class="[r.color, 'flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-muted']">
                        <component :is="r.icon" class="h-4 w-4" />
                    </div>
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2">
                            <p class="text-sm font-medium text-foreground">{{ r.title }}</p>
                            <span :class="typeColor[r.type]" class="text-[10px] font-semibold rounded-full px-2 py-0.5">
                                {{ r.type }}
                            </span>
                        </div>
                        <p class="text-xs text-muted-foreground truncate">{{ r.description }}</p>
                    </div>
                </div>
                <div v-if="results.length === 0 && query.length > 0" class="py-12 text-center text-sm text-muted-foreground">
                    No results found for "{{ query }}"
                </div>
            </div>
        </div>
    </div>
</template>

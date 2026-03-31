<script setup lang="ts">
import {
    LayoutDashboard,
    FolderKanban,
    Coins,
    BookOpen,
    Building2,
    Users,
    Target,
    BarChart3,
    Activity,
    Leaf,
} from 'lucide-vue-next';

const collapsed = useState('sidebar-collapsed', () => false);

const navItems = [
    { label: 'Dashboard', icon: LayoutDashboard, to: '/' },
    { label: 'Projects', icon: FolderKanban, to: '/projects' },
    { label: 'Credits', icon: Coins, to: '/credits' },
    { label: 'Methodologies', icon: BookOpen, to: '/methodologies' },
    { label: 'Registries', icon: Building2, to: '/registries' },
    { label: 'Developers', icon: Users, to: '/developers' },
    { label: 'SDGs', icon: Target, to: '/sdgs' },
    { label: 'Analytics', icon: BarChart3, to: '/analytics' },
    { label: 'Sync Status', icon: Activity, to: '/status' },
];
</script>

<template>
    <aside
        class="sticky top-0 flex h-screen flex-col border-r bg-card text-sidebar-foreground transition-all duration-300"
        :class="collapsed ? 'w-[var(--sidebar-width-collapsed)]' : 'w-[var(--sidebar-width)]'"
    >
        <!-- Logo -->
        <div class="flex h-12 items-center gap-2.5 px-4">
            <div class="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-primary">
                <Leaf class="h-3.5 w-3.5 text-primary-foreground" />
            </div>
            <div v-if="!collapsed" class="flex items-baseline gap-1.5">
                <span class="text-sm font-semibold text-foreground">Sustainable</span>
                <span class="text-xs text-muted-foreground">Explorer</span>
            </div>
        </div>

        <!-- Navigation -->
        <nav class="flex-1 space-y-0.5 px-2 pt-1 overflow-y-auto">
            <NuxtLink
                v-for="item in navItems"
                :key="item.to"
                :to="item.to"
                class="group flex items-center gap-3 rounded-lg px-3 py-[7px] text-[13px] font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                active-class="!bg-primary/8 !text-primary !font-semibold"
            >
                <component
                    :is="item.icon"
                    class="h-[18px] w-[18px] shrink-0 transition-colors group-hover:text-foreground"
                />
                <span v-if="!collapsed" class="truncate">{{ item.label }}</span>
            </NuxtLink>
        </nav>
    </aside>
</template>

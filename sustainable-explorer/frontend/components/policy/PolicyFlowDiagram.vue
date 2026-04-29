<script setup lang="ts">
import { computed, watch } from 'vue';
import { VueFlow, Position, MarkerType } from '@vue-flow/core';
import { Background } from '@vue-flow/background';
import { Controls } from '@vue-flow/controls';
import { MiniMap } from '@vue-flow/minimap';
import dagre from 'dagre';
import type { PolicyBlock } from '~/types/policy';
import {
    categorizeBlockType,
    CATEGORY_STYLES,
    type BlockCategory,
} from '~/utils/policy-block-categories';

import '@vue-flow/core/dist/style.css';
import '@vue-flow/core/dist/theme-default.css';
import '@vue-flow/controls/dist/style.css';
import '@vue-flow/minimap/dist/style.css';

interface Props {
    config: PolicyBlock | null;
}
const props = defineProps<Props>();

const emit = defineEmits<{
    (e: 'select-block', block: PolicyBlock): void;
}>();

interface FlowNodeData {
    block: PolicyBlock;
    category: BlockCategory;
    label: string;
    blockType: string;
}

interface FlowNode {
    id: string;
    type: 'default';
    position: { x: number; y: number };
    data: FlowNodeData;
    sourcePosition: Position;
    targetPosition: Position;
    style?: Record<string, string>;
}

interface FlowEdge {
    id: string;
    source: string;
    target: string;
    type: 'smoothstep';
    animated?: boolean;
    style?: Record<string, string>;
    markerEnd?: { type: MarkerType; color?: string };
    label?: string;
}

const NODE_W = 240;
const NODE_H = 72;

function walkBlocks(
    block: PolicyBlock,
    nodes: FlowNode[],
    edges: FlowEdge[],
    parentId: string | null,
    depth: number,
    idCounter: { n: number },
    tagToId: Map<string, string>,
): void {
    const id = block.id ?? `gen-${idCounter.n++}`;
    const blockType = block.blockType ?? 'unknown';
    const category = categorizeBlockType(blockType);
    const label = block.tag || blockType;

    if (block.tag && !tagToId.has(block.tag)) {
        tagToId.set(block.tag, id);
    }

    nodes.push({
        id,
        type: 'default',
        position: { x: 0, y: 0 }, // dagre fills this in
        data: { block, category, label, blockType },
        sourcePosition: Position.Bottom,
        targetPosition: Position.Top,
    });

    if (parentId) {
        edges.push({
            id: `e-${parentId}-${id}`,
            source: parentId,
            target: id,
            type: 'smoothstep',
            style: { stroke: '#94a3b8', strokeWidth: '1.5' },
            markerEnd: { type: MarkerType.ArrowClosed, color: '#94a3b8' },
        });
    }

    const children = Array.isArray(block.children) ? block.children : [];
    for (const child of children) {
        walkBlocks(child, nodes, edges, id, depth + 1, idCounter, tagToId);
    }
}

function addDependencyEdges(
    block: PolicyBlock,
    edges: FlowEdge[],
    tagToId: Map<string, string>,
): void {
    const blockId = block.id;
    const deps = Array.isArray(block.dependencies) ? block.dependencies : [];
    for (const depTag of deps) {
        const depId = tagToId.get(depTag);
        if (!blockId || !depId) continue;
        edges.push({
            id: `dep-${depId}-${blockId}`,
            source: depId,
            target: blockId,
            type: 'smoothstep',
            animated: true,
            style: { stroke: '#f59e0b', strokeWidth: '1.5', strokeDasharray: '4 3' },
            markerEnd: { type: MarkerType.ArrowClosed, color: '#f59e0b' },
            label: 'depends',
        });
    }
    const children = Array.isArray(block.children) ? block.children : [];
    for (const child of children) {
        addDependencyEdges(child, edges, tagToId);
    }
}

function layoutWithDagre(nodes: FlowNode[], edges: FlowEdge[]): void {
    const g = new dagre.graphlib.Graph();
    g.setGraph({ rankdir: 'TB', nodesep: 60, ranksep: 80, marginx: 20, marginy: 20 });
    g.setDefaultEdgeLabel(() => ({}));

    for (const n of nodes) {
        g.setNode(n.id, { width: NODE_W, height: NODE_H });
    }
    for (const e of edges) {
        // Don't include dependency (animated) edges in layout — they distort the tree.
        if (!e.animated) g.setEdge(e.source, e.target);
    }

    dagre.layout(g);

    for (const n of nodes) {
        const pos = g.node(n.id);
        if (pos) {
            n.position = { x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2 };
        }
    }
}

const elements = computed(() => {
    if (!props.config) return { nodes: [] as FlowNode[], edges: [] as FlowEdge[] };

    const nodes: FlowNode[] = [];
    const edges: FlowEdge[] = [];
    const tagToId = new Map<string, string>();
    const idCounter = { n: 0 };

    walkBlocks(props.config, nodes, edges, null, 0, idCounter, tagToId);
    addDependencyEdges(props.config, edges, tagToId);
    layoutWithDagre(nodes, edges);

    return { nodes, edges };
});

const stats = computed(() => {
    const counts: Record<BlockCategory, number> = {
        ui: 0, role: 0, schema: 0, token: 0, info: 0, logic: 0, integration: 0, unknown: 0,
    };
    for (const n of elements.value.nodes) {
        counts[n.data.category] = (counts[n.data.category] ?? 0) + 1;
    }
    return counts;
});

const totalNodes = computed(() => elements.value.nodes.length);

function onNodeClick(event: { node: FlowNode }) {
    emit('select-block', event.node.data.block);
}

// Re-fit on config change
const flowKey = ref(0);
watch(
    () => props.config,
    () => { flowKey.value++; },
);
</script>

<template>
    <div class="relative w-full h-full">
        <ClientOnly>
            <VueFlow
                :key="flowKey"
                :nodes="elements.nodes"
                :edges="elements.edges"
                :nodes-draggable="false"
                :nodes-connectable="false"
                :elements-selectable="true"
                :fit-view-on-init="true"
                :default-edge-options="{ type: 'smoothstep' }"
                class="policy-flow"
                @node-click="onNodeClick"
            >
                <template #node-default="{ data }">
                    <div
                        :class="[
                            'rounded-lg border-2 px-3 py-2 shadow-sm cursor-pointer transition-all hover:shadow-md min-w-[210px]',
                            CATEGORY_STYLES[(data as FlowNodeData).category].bg,
                            CATEGORY_STYLES[(data as FlowNodeData).category].border,
                        ]"
                    >
                        <div class="flex items-center gap-2">
                            <span
                                :class="[
                                    'h-2 w-2 rounded-full shrink-0',
                                    CATEGORY_STYLES[(data as FlowNodeData).category].dot,
                                ]"
                            />
                            <div class="min-w-0 flex-1">
                                <div
                                    :class="[
                                        'text-sm font-semibold truncate',
                                        CATEGORY_STYLES[(data as FlowNodeData).category].text,
                                    ]"
                                    :title="(data as FlowNodeData).label"
                                >
                                    {{ (data as FlowNodeData).label }}
                                </div>
                                <div class="text-[10px] font-mono text-muted-foreground truncate">
                                    {{ (data as FlowNodeData).blockType }}
                                </div>
                            </div>
                        </div>
                    </div>
                </template>

                <Background pattern-color="#e5e7eb" :gap="20" />
                <Controls position="bottom-left" :show-interactive="false" />
                <MiniMap
                    pannable
                    zoomable
                    :node-color="(n: any) => {
                        const cat = (n.data?.category ?? 'unknown') as BlockCategory;
                        return ({
                            ui: '#3b82f6',
                            role: '#a855f7',
                            schema: '#10b981',
                            token: '#f59e0b',
                            info: '#64748b',
                            logic: '#f43f5e',
                            integration: '#06b6d4',
                            unknown: '#9ca3af',
                        }[cat]);
                    }"
                    mask-color="rgba(255,255,255,0.6)"
                />
            </VueFlow>

            <template #fallback>
                <div class="flex h-full items-center justify-center text-sm text-muted-foreground">
                    Loading diagram…
                </div>
            </template>
        </ClientOnly>

        <!-- Legend -->
        <div
            class="absolute top-3 right-3 z-10 rounded-md border bg-card/95 backdrop-blur px-3 py-2 shadow-sm text-xs"
        >
            <div class="font-medium mb-1.5 text-foreground">
                {{ totalNodes }} block{{ totalNodes === 1 ? '' : 's' }}
            </div>
            <div class="grid grid-cols-2 gap-x-3 gap-y-1">
                <div
                    v-for="(count, cat) in stats"
                    v-show="count > 0"
                    :key="cat"
                    class="flex items-center gap-1.5"
                >
                    <span :class="['h-2 w-2 rounded-full', CATEGORY_STYLES[cat as BlockCategory].dot]" />
                    <span class="text-muted-foreground">
                        {{ CATEGORY_STYLES[cat as BlockCategory].label }} ({{ count }})
                    </span>
                </div>
            </div>
        </div>
    </div>
</template>

<style scoped>
.policy-flow {
    width: 100%;
    height: 100%;
}
:deep(.vue-flow__node-default) {
    padding: 0;
    border: none;
    background: transparent;
    width: auto;
}
:deep(.vue-flow__node-default.selected) {
    box-shadow: none;
}
</style>

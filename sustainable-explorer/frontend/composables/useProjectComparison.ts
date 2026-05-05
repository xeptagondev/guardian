interface ComparisonEntry {
    id: string;
    name: string;
}

const selectedEntries = ref<ComparisonEntry[]>([]);

export function useProjectComparison() {
    const selectedIds = computed(() => selectedEntries.value.map(e => e.id));

    const canAdd = computed(() => selectedEntries.value.length < 4);

    function isSelected(id: string): boolean {
        return selectedEntries.value.some(e => e.id === id);
    }

    function toggleProject(id: string, name: string) {
        const idx = selectedEntries.value.findIndex(e => e.id === id);
        if (idx !== -1) {
            selectedEntries.value = selectedEntries.value.filter(e => e.id !== id);
        } else if (selectedEntries.value.length < 4) {
            selectedEntries.value = [...selectedEntries.value, { id, name }];
        }
    }

    function clearAll() {
        selectedEntries.value = [];
    }

    return {
        selectedIds,
        selectedEntries: computed(() => selectedEntries.value),
        canAdd,
        isSelected,
        toggleProject,
        clearAll,
    };
}

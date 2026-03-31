export type SortDirection = 'asc' | 'desc' | null;

export function useFilteredPagination<T>(
    items: Ref<T[]> | T[],
    opts: {
        searchFields: (keyof T)[];
        pageSize?: number;
        arrayFields?: (keyof T)[];
        defaultSort?: { key: keyof T; dir: 'asc' | 'desc' };
    },
) {
    const searchQuery = ref('');
    const currentPage = ref(1);
    const pageSize = opts.pageSize ?? 10;
    const activeFilters = ref<Record<string, string>>({});
    const sortKey = ref<keyof T | null>(opts.defaultSort?.key ?? null) as Ref<keyof T | null>;
    const sortDir = ref<SortDirection>(opts.defaultSort?.dir ?? null);

    function toggleSort(key: keyof T) {
        if (sortKey.value === key) {
            if (sortDir.value === 'asc') {
                sortDir.value = 'desc';
            } else if (sortDir.value === 'desc') {
                sortKey.value = null;
                sortDir.value = null;
            } else {
                sortDir.value = 'asc';
            }
        } else {
            sortKey.value = key;
            sortDir.value = 'asc';
        }
        currentPage.value = 1;
    }

    const filtered = computed(() => {
        const all = unref(items);
        let result = all;

        // Text search
        const q = searchQuery.value.trim().toLowerCase();
        if (q) {
            result = result.filter((item) =>
                opts.searchFields.some((field) => {
                    const val = item[field];
                    return typeof val === 'string' && val.toLowerCase().includes(q);
                }),
            );
        }

        // Dropdown filters
        const arrayFieldSet = new Set(opts.arrayFields?.map(String) ?? []);
        for (const [key, value] of Object.entries(activeFilters.value)) {
            if (value && value !== 'all') {
                if (arrayFieldSet.has(key)) {
                    const selectedValues = value.split(',');
                    result = result.filter((item) => {
                        const arr = item[key as keyof T];
                        if (!Array.isArray(arr)) return false;
                        return selectedValues.some(v => arr.map(String).includes(v));
                    });
                } else if (value.includes(',')) {
                    const selectedValues = value.split(',');
                    result = result.filter((item) => selectedValues.includes(String(item[key as keyof T])));
                } else {
                    result = result.filter((item) => String(item[key as keyof T]) === value);
                }
            }
        }

        // Sort
        if (sortKey.value && sortDir.value) {
            const key = sortKey.value;
            const dir = sortDir.value === 'asc' ? 1 : -1;
            result = [...result].sort((a, b) => {
                const aVal = a[key];
                const bVal = b[key];
                if (aVal == null && bVal == null) return 0;
                if (aVal == null) return 1;
                if (bVal == null) return -1;
                if (typeof aVal === 'number' && typeof bVal === 'number') {
                    return (aVal - bVal) * dir;
                }
                return String(aVal).localeCompare(String(bVal)) * dir;
            });
        }

        return result;
    });

    const totalPages = computed(() => Math.max(1, Math.ceil(filtered.value.length / pageSize)));

    const paginated = computed(() => {
        const start = (currentPage.value - 1) * pageSize;
        return filtered.value.slice(start, start + pageSize);
    });

    function setFilter(key: string, value: string) {
        activeFilters.value = { ...activeFilters.value, [key]: value };
        currentPage.value = 1;
    }

    function clearFilters() {
        activeFilters.value = {};
        searchQuery.value = '';
        currentPage.value = 1;
    }

    watch(searchQuery, () => {
        currentPage.value = 1;
    });

    return {
        searchQuery,
        currentPage,
        pageSize,
        activeFilters,
        filtered,
        paginated,
        totalPages,
        sortKey,
        sortDir,
        toggleSort,
        setFilter,
        clearFilters,
    };
}

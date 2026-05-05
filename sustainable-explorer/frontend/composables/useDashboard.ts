import { MOCK_PROJECTS, MOCK_CREDITS, MOCK_RETIREMENTS } from '~/data';
import type { ActivityItem, MapPoint, MapCountry } from '~/types/models';
import { formatCredits } from '~/lib/format';
import { useSummaryApi } from './api/useSummaryApi';
import { useRegistriesApi } from './api/useRegistriesApi';
import { useProjectsApi } from './api/useProjectsApi';
import { useMethodologiesApi } from './api/useMethodologiesApi';
import { useGeocodedCountries } from './useGeocodedCountries';

export function useDashboard(
    filters?: Ref<{ developer?: string; registry?: string }>,
    network?: Ref<string>,
) {
    const developerOptions = computed(() => {
        return ['All Developers', ...new Set(MOCK_PROJECTS.map(p => p.developer))].sort((a, b) => {
            if (a === 'All Developers') return -1;
            if (b === 'All Developers') return 1;
            return a.localeCompare(b);
        });
    });

    const registryOptions = computed(() => {
        return ['All Registries', ...new Set(MOCK_PROJECTS.map(p => p.registry))].sort((a, b) => {
            if (a === 'All Registries') return -1;
            if (b === 'All Registries') return 1;
            return a.localeCompare(b);
        });
    });

    // Filter projects based on dashboard filters
    const filteredProjects = computed(() => {
        let result = [...MOCK_PROJECTS];
        if (filters?.value) {
            const f = filters.value;
            if (f.developer && f.developer !== 'All Developers') {
                result = result.filter(p => p.developer === f.developer);
            }
            if (f.registry && f.registry !== 'All Registries') {
                result = result.filter(p => p.registry === f.registry);
            }
        }
        return result;
    });

    const filteredCredits = computed(() => {
        let result = [...MOCK_CREDITS];
        if (filters?.value) {
            const f = filters.value;
            if (f.registry && f.registry !== 'All Registries') {
                result = result.filter(c => c.registry === f.registry);
            }
            // Filter credits by developer through their linked projects
            if (f.developer && f.developer !== 'All Developers') {
                const projectIds = new Set(filteredProjects.value.map(p => p.id));
                result = result.filter(c => projectIds.has(c.projectId));
            }
        }
        return result;
    });

    // Aggregation helper: group date/value pairs by period
    const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const quarterNames = ['Q1', 'Q2', 'Q3', 'Q4'];

    function aggregateByPeriod(
        entries: { date: string; value: number }[],
        period: 'monthly' | 'quarterly' | 'yearly',
    ): { label: string; value: number }[] {
        const map: Record<string, number> = {};

        for (const e of entries) {
            const d = new Date(e.date);
            let key: string;
            let label: string;
            if (period === 'yearly') {
                key = String(d.getFullYear());
                label = key;
            } else if (period === 'quarterly') {
                const q = Math.floor(d.getMonth() / 3);
                key = `${d.getFullYear()}-Q${q}`;
                label = `${quarterNames[q]} ${d.getFullYear()}`;
            } else {
                key = `${d.getFullYear()}-${String(d.getMonth()).padStart(2, '0')}`;
                label = `${monthNames[d.getMonth()]} ${String(d.getFullYear()).slice(2)}`;
            }
            map[key] = (map[key] || 0) + e.value;
        }

        return Object.entries(map)
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([, value]) => {
                // reverse-lookup label from sorted entries
                return { label: '', value: Math.max(Math.round(value), 1) };
            });
    }

    // Build issuance time series from filtered projects
    function buildIssuanceSeries(period: 'monthly' | 'quarterly' | 'yearly'): { label: string; value: number }[] {
        const map: Record<string, { sortKey: string; label: string; value: number }> = {};

        for (const p of filteredProjects.value) {
            const d = new Date(p.createdAt);
            const val = p.credits / 1000000;
            let sortKey: string;
            let label: string;
            if (period === 'yearly') {
                sortKey = String(d.getFullYear());
                label = sortKey;
            } else if (period === 'quarterly') {
                const q = Math.floor(d.getMonth() / 3);
                sortKey = `${d.getFullYear()}-Q${q}`;
                label = `${quarterNames[q]} '${String(d.getFullYear()).slice(2)}`;
            } else {
                sortKey = `${d.getFullYear()}-${String(d.getMonth()).padStart(2, '0')}`;
                label = `${monthNames[d.getMonth()]} '${String(d.getFullYear()).slice(2)}`;
            }
            if (!map[sortKey]) map[sortKey] = { sortKey, label, value: 0 };
            map[sortKey].value += val;
        }

        return Object.values(map)
            .sort((a, b) => a.sortKey.localeCompare(b.sortKey))
            .map(e => ({ label: e.label, value: Math.max(Math.round(e.value * 10) / 10, 0.1) }));
    }

    function buildRetirementSeries(period: 'monthly' | 'quarterly' | 'yearly'): { label: string; value: number }[] {
        const map: Record<string, { sortKey: string; label: string; value: number }> = {};

        for (const r of filteredRetirements.value) {
            const d = new Date(r.date);
            const val = r.quantity / 1000000;
            let sortKey: string;
            let label: string;
            if (period === 'yearly') {
                sortKey = String(d.getFullYear());
                label = sortKey;
            } else if (period === 'quarterly') {
                const q = Math.floor(d.getMonth() / 3);
                sortKey = `${d.getFullYear()}-Q${q}`;
                label = `${quarterNames[q]} '${String(d.getFullYear()).slice(2)}`;
            } else {
                sortKey = `${d.getFullYear()}-${String(d.getMonth()).padStart(2, '0')}`;
                label = `${monthNames[d.getMonth()]} '${String(d.getFullYear()).slice(2)}`;
            }
            if (!map[sortKey]) map[sortKey] = { sortKey, label, value: 0 };
            map[sortKey].value += val;
        }

        return Object.values(map)
            .sort((a, b) => a.sortKey.localeCompare(b.sortKey))
            .map(e => ({ label: e.label, value: Math.max(Math.round(e.value * 10) / 10, 0.1) }));
    }

    // Keep backward-compat computed values (default monthly)
    const issuanceMonths = computed(() => buildIssuanceSeries('monthly'));
    const issuanceMax = computed(() => {
        const vals = issuanceMonths.value.map(m => m.value);
        return vals.length > 0 ? Math.max(...vals) : 1;
    });
    const issuanceTotal = computed(() =>
        Math.round(issuanceMonths.value.reduce((sum, m) => sum + m.value, 0) * 10) / 10,
    );

    // Recent activity derived from the most recent projects and credits
    const recentActivity = computed<ActivityItem[]>(() => {
        const activities: ActivityItem[] = [];

        // Sort projects by createdAt descending
        const sortedProjects = [...filteredProjects.value].sort(
            (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
        );

        // Generate activity items from recent projects/credits
        if (sortedProjects.length > 0) {
            activities.push({
                time: '2 min ago',
                action: 'New project registered',
                detail: `${sortedProjects[0].name} — ${sortedProjects[0].registry}`,
                type: 'project',
            });
        }

        const sortedCredits = [...filteredCredits.value].sort(
            (a, b) => new Date(b.mintDate).getTime() - new Date(a.mintDate).getTime(),
        );

        if (sortedCredits.length > 0) {
            activities.push({
                time: '8 min ago',
                action: 'Issuances minted',
                detail: `${formatCredits(sortedCredits[0].supply)} — ${sortedCredits[0].name}`,
                type: 'credit',
            });
        }

        if (sortedProjects.length > 1) {
            activities.push({
                time: '15 min ago',
                action: 'Policy published',
                detail: `${sortedProjects[1].methodology} — ${sortedProjects[1].registry}`,
                type: 'policy',
            });
        }

        if (sortedProjects.length > 2) {
            activities.push({
                time: '23 min ago',
                action: 'Verification completed',
                detail: `${sortedProjects[2].name} — ${sortedProjects[2].registry}`,
                type: 'verification',
            });
        }

        // Registry join
        const registryList = [...new Set(filteredProjects.value.map(p => p.registry))];
        if (registryList.length > 0) {
            activities.push({
                time: '1 hour ago',
                action: 'New registry joined',
                detail: registryList[registryList.length - 1],
                type: 'registry',
            });
        }

        if (sortedCredits.length > 1) {
            activities.push({
                time: '2 hours ago',
                action: 'Issuances retired',
                detail: `${formatCredits(Math.round(sortedCredits[1].supply * 0.1))} — ${sortedCredits[1].name}`,
                type: 'retirement',
            });
        }

        return activities;
    });

    // Stats active filter flag (still driven by mock filter state)
    const hasActiveFilter = computed(() => {
        if (!filters?.value) return false;
        const f = filters.value;
        return (f.developer && f.developer !== 'All Developers') || (f.registry && f.registry !== 'All Registries');
    });

    // Sector breakdown for pie charts
    const sectorColors: Record<string, string> = {
        'Energy Industries': 'hsl(142, 76%, 36%)',
        'Energy Demand': 'hsl(197, 37%, 24%)',
        'Forestry and Land Use': 'hsl(47, 96%, 53%)',
        'Waste Handling and Disposal': 'hsl(349, 89%, 60%)',
        'Agriculture': 'hsl(262, 83%, 58%)',
        'Coastal and Marine': 'hsl(199, 89%, 48%)',
        'Water Supply': 'hsl(217, 71%, 53%)',
    };

    const sectorBreakdown = computed(() => {
        const groups: Record<string, { projectCount: number; creditCount: number }> = {};
        for (const p of filteredProjects.value) {
            if (!groups[p.sector]) {
                groups[p.sector] = { projectCount: 0, creditCount: 0 };
            }
            groups[p.sector].projectCount++;
            groups[p.sector].creditCount += p.credits;
        }
        return Object.entries(groups)
            .map(([label, data]) => ({
                label,
                projectCount: data.projectCount,
                creditCount: data.creditCount,
                color: sectorColors[label] || 'hsl(220, 13%, 69%)',
            }))
            .sort((a, b) => b.projectCount - a.projectCount);
    });

    // Registry breakdown for pie charts
    const registryColors: Record<string, string> = {
        'Verra': 'hsl(142, 76%, 36%)',
        'Gold Standard': 'hsl(47, 96%, 53%)',
        'CAR': 'hsl(349, 89%, 60%)',
        'ACR': 'hsl(262, 83%, 58%)',
    };

    const registryBreakdown = computed(() => {
        const groups: Record<string, { projectCount: number; creditCount: number }> = {};
        for (const p of filteredProjects.value) {
            if (!groups[p.registry]) {
                groups[p.registry] = { projectCount: 0, creditCount: 0 };
            }
            groups[p.registry].projectCount++;
            groups[p.registry].creditCount += p.credits;
        }
        return Object.entries(groups)
            .map(([label, data]) => ({
                label,
                projectCount: data.projectCount,
                creditCount: data.creditCount,
                color: registryColors[label] || 'hsl(220, 13%, 69%)',
            }))
            .sort((a, b) => b.projectCount - a.projectCount);
    });

    // Total retired from mock retirements, filtered by relevant projects
    const filteredRetirements = computed(() => {
        const projectIds = new Set(filteredProjects.value.map(p => p.id));
        return MOCK_RETIREMENTS.filter(r => projectIds.has(r.projectId));
    });

    // Retirement trend by month
    const retirementMonths = computed(() => {
        const monthMap: Record<string, number> = {};
        const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

        for (const r of filteredRetirements.value) {
            const date = new Date(r.date);
            const key = `${date.getFullYear()}-${String(date.getMonth()).padStart(2, '0')}`;
            monthMap[key] = (monthMap[key] || 0) + Math.round(r.quantity / 1000000) || 1;
        }

        return Object.entries(monthMap)
            .sort((a, b) => a[0].localeCompare(b[0]))
            .slice(-6)
            .map(([key, value]) => {
                const [, monthIdx] = key.split('-');
                return { month: monthNames[parseInt(monthIdx)], value: Math.max(value, 1) };
            });
    });

    const retirementMax = computed(() => {
        const vals = retirementMonths.value.map(m => m.value);
        return vals.length > 0 ? Math.max(...vals) : 1;
    });

    const retirementTotal = computed(() => retirementMonths.value.reduce((sum, m) => sum + m.value, 0));

    // Vintage distribution
    const vintageDistribution = computed(() => {
        const vintageMap: Record<string, { projects: number; credits: number }> = {};
        for (const p of filteredProjects.value) {
            if (!vintageMap[p.vintage]) vintageMap[p.vintage] = { projects: 0, credits: 0 };
            vintageMap[p.vintage].projects++;
            vintageMap[p.vintage].credits += p.credits;
        }
        return Object.entries(vintageMap)
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([year, data]) => ({ year, projects: data.projects, credits: data.credits }));
    });

    const vintageMax = computed(() => {
        const vals = vintageDistribution.value.map(v => v.credits);
        return vals.length > 0 ? Math.max(...vals) : 1;
    });

    // -----------------------------------------------------------------------
    // Real API calls — stat cards, top registries, map/country data
    // -----------------------------------------------------------------------

    const _network = network ?? ref('mainnet');

    // -- Real API: summary totals for stat cards --
    const { data: summaryData } = useSummaryApi({ network: _network });

    // -- Real API: registry count (meta.total) --
    const { data: registriesCountData } = useRegistriesApi({
        page: ref(1), limit: ref(1), search: ref(''),
        network: _network, sortBy: ref(null), sortDir: ref(null),
    });

    // -- Real API: methodology count (meta.total) --
    const { data: methodologiesCountData } = useMethodologiesApi({
        page: ref(1), limit: ref(1), search: ref(''),
        network: _network, sortBy: ref(null), sortDir: ref(null),
    });

    // -- Real API: project count (meta.total) --
    const { meta: projectsCountMeta } = useProjectsApi({
        page: ref(1), limit: ref(1), search: ref(''),
        network: _network, sortBy: ref(null), sortDir: ref(null),
    });

    // -- Real API: top registries for table --
    const { data: topRegistriesData } = useRegistriesApi({
        page: ref(1), limit: ref(10), search: ref(''),
        network: _network, sortBy: ref('projects'), sortDir: ref('desc'),
    });

    // -- Real API: project batch for map/country data --
    const { projects: projectsBatch } = useProjectsApi({
        page: ref(1), limit: ref(100), search: ref(''),
        network: _network, sortBy: ref('credits'), sortDir: ref('desc'),
    });

    // -----------------------------------------------------------------------
    // Overrides: use real API data instead of mock-backed computeds
    // -----------------------------------------------------------------------

    // Override stats — use real counts, fall back to 0 when data isn't loaded yet
    const stats = computed(() => {
        const registryCount = registriesCountData.value?.meta.total ?? 0;
        const methodologyCount = methodologiesCountData.value?.meta.total ?? 0;
        const projectCount = projectsCountMeta.value?.total ?? 0;
        const totalCredits = summaryData.value?.totalIssued ?? 0;
        const totalRetiredVal = summaryData.value?.totalRetired ?? 0;
        return {
            registries: registryCount,
            methodologies: methodologyCount,
            projects: projectCount,
            totalCredits,
            totalRetired: totalRetiredVal,
        };
    });

    // Override totalRetired — use real API summary
    const totalRetired = computed(() => summaryData.value?.totalRetired ?? 0);

    // Override registries — replace mock-backed with real API
    const registries = computed(() => {
        const rows = topRegistriesData.value?.data ?? [];
        return rows.map(r => ({
            name: r.name ?? r.did ?? 'Unknown',
            policies: r.stats?.policyCount ?? 0,
            projects: r.stats?.projectCount ?? 0,
            credits: formatCredits(r.stats?.issuanceCount ?? 0),
        }));
    });

    // Real projects from API batch — already mapped to Project[] by useProjectsApi
    const _realProjects = computed(() => projectsBatch.value);

    // Reverse geocode UNK country codes from lat/lng (same as projects page)
    const { resolvedCode } = useGeocodedCountries(_realProjects);

    // Override vintageDistribution — group real projects by vintage
    // Prefer totalIssued (actual minted); fall back to credits (ER_y estimate) if zero
    const vintageDistributionReal = computed(() => {
        const vintageMap: Record<string, { projects: number; credits: number }> = {};
        for (const p of _realProjects.value) {
            const year = p.vintage;
            if (!year) continue;
            if (!vintageMap[year]) vintageMap[year] = { projects: 0, credits: 0 };
            vintageMap[year].projects++;
            vintageMap[year].credits += p.totalIssued ?? 0;
        }
        return Object.entries(vintageMap)
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([year, data]) => ({ year, projects: data.projects, credits: data.credits }));
    });

    const vintageMaxReal = computed(() => {
        const vals = vintageDistributionReal.value.map(v => v.credits);
        return vals.length > 0 ? Math.max(...vals) : 1;
    });

    // Override registryBreakdown — group real projects by registryName
    const fallbackColors = [
        'hsl(197, 71%, 52%)',
        'hsl(271, 81%, 56%)',
        'hsl(338, 85%, 55%)',
        'hsl(24, 95%, 53%)',
        'hsl(162, 63%, 41%)',
        'hsl(217, 71%, 53%)',
        'hsl(45, 93%, 47%)',
    ];
    const registryBreakdownReal = computed(() => {
        const groups: Record<string, { projectCount: number; creditCount: number }> = {};
        for (const p of _realProjects.value) {
            const name = p.registry || 'Unknown Registry';
            if (!groups[name]) groups[name] = { projectCount: 0, creditCount: 0 };
            groups[name].projectCount++;
            groups[name].creditCount += p.totalIssued ?? 0;
        }
        let fallbackIdx = 0;
        return Object.entries(groups)
            .map(([label, data]) => ({
                label,
                projectCount: data.projectCount,
                creditCount: data.creditCount,
                color: registryColors[label] || fallbackColors[fallbackIdx++ % fallbackColors.length],
            }))
            .sort((a, b) => b.projectCount - a.projectCount);
    });

    // Override countries — aggregate from real projects batch
    const countries = computed(() => {
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        const countryMap: Record<string, {
            name: string; flag: string; code: string; projects: number;
            credits: number; methodologies: Set<string>;
            developer: string; registry: string;
        }> = {};

        for (const p of _realProjects.value) {
            const code = resolvedCode(p);
            if (!code || code === 'UNK') continue;
            if (!countryMap[code]) {
                countryMap[code] = {
                    name: p.country || code,
                    flag: p.flag,
                    code,
                    projects: 0,
                    credits: 0,
                    methodologies: new Set(),
                    developer: p.developer,
                    registry: p.registry,
                };
            }
            countryMap[code].projects++;
            countryMap[code].credits += p.credits ?? 0;
            if (p.methodologyId) countryMap[code].methodologies.add(p.methodologyId);
        }

        return Object.values(countryMap)
            .map(c => ({
                name: c.name,
                flag: c.flag,
                code: c.code,
                projects: c.projects,
                credits: formatCredits(c.credits),
                methodologies: c.methodologies.size,
                developer: c.developer,
                registry: c.registry,
            }))
            .sort((a, b) => b.projects - a.projects);
    });

    // Override mapCountries
    const mapCountries = computed<MapCountry[]>(() =>
        countries.value.map(c => ({
            country: c.name,
            countryCode: c.code,
            projects: c.projects,
            credits: c.credits,
        })),
    );

    // Override mapPoints
    const mapPoints = computed<MapPoint[]>(() =>
        _realProjects.value
            .filter(p => p.lat != null && p.lng != null)
            .map(p => ({
                name: p.name,
                lat: p.lat!,
                lng: p.lng!,
                credits: formatCredits(p.credits ?? 0),
            })),
    );

    // Country detail for the side panel — uses _realProjects instead of filteredProjects
    function getCountryDetail(code: string) {
        const countryData = countries.value.find(c => c.code === code);
        if (!countryData) return null;

        // Get projects for this country from real API batch
        const countryProjects = _realProjects.value.filter(p => resolvedCode(p) === code);

        // Build sector breakdown from project categories
        const catCredits: Record<string, number> = {};
        let totalCredits = 0;
        for (const p of countryProjects) {
            catCredits[p.category] = (catCredits[p.category] || 0) + p.credits;
            totalCredits += p.credits;
        }

        const sectorColorMap: Record<string, string> = {
            'Renewable Energy': '#1a9850',
            'Forestry': '#0f6b3a',
            'Blue Carbon': '#0a97d9',
            'Energy Efficiency': '#66bd63',
            'Agriculture': '#d9ef8b',
            'Water': '#26bde2',
            'Waste': '#a6d96a',
        };

        const sectors = Object.entries(catCredits)
            .map(([label, credits]) => ({
                label,
                value: totalCredits > 0 ? Math.round((credits / totalCredits) * 100) : 0,
                color: sectorColorMap[label] || '#d4d4d8',
            }))
            .sort((a, b) => b.value - a.value);

        // Registry breakdown
        const regCredits: Record<string, number> = {};
        for (const p of countryProjects) {
            regCredits[p.registry] = (regCredits[p.registry] || 0) + p.credits;
        }
        const regList = Object.entries(regCredits)
            .map(([name, credits]) => ({
                name,
                pct: totalCredits > 0 ? Math.round((credits / totalCredits) * 1000) / 10 : 0,
            }))
            .sort((a, b) => b.pct - a.pct)
            .slice(0, 3);

        return {
            name: countryData.name,
            flag: countryData.flag,
            projects: countryData.projects,
            credits: countryData.credits,
            totalReduction: String(Math.round(countryData.projects * 5.2)),
            annualReduction: String(Math.round(countryData.projects * 2.8)),
            sectors,
            registries: regList,
        };
    }

    return {
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
        registryBreakdown: registryBreakdownReal,
        developerOptions,
        registryOptions,
        getCountryDetail,
        totalRetired,
        retirementMonths,
        retirementMax,
        retirementTotal,
        vintageDistribution: vintageDistributionReal,
        vintageMax: vintageMaxReal,
        buildIssuanceSeries,
        buildRetirementSeries,
        _realProjects,
    };
}

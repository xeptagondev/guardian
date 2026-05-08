import { MOCK_PROJECTS, MOCK_CREDITS, MOCK_RETIREMENTS } from '~/data';
import type { ActivityItem, MapPoint, MapCountry } from '~/types/models';
import { formatCredits } from '~/lib/format';
import { getSectorColor } from '~/lib/enums';
import { useDashboardSummaryApi } from './api/useSummaryApi';
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

    // Build issuance time series from real API timeline data.
    // Backend returns monthly granularity; quarterly/yearly are aggregated here
    // so a single API call serves all three period modes with no re-fetching.
    function buildIssuanceSeries(period: 'monthly' | 'quarterly' | 'yearly'): { label: string; value: number }[] {
        const points = rawTimeline.value ?? [];
        if (points.length === 0) return [];

        if (period === 'monthly') {
            return points.map(p => {
                const [year, month] = p.period.split('-');
                const label = `${monthNames[parseInt(month, 10) - 1]} '${year.slice(2)}`;
                return { label, value: Math.max(Math.round(p.totalIssued / 1_000_000 * 10) / 10, 0.1) };
            });
        }

        if (period === 'quarterly') {
            const map: Record<string, { sortKey: string; label: string; total: number }> = {};
            for (const p of points) {
                const [year, month] = p.period.split('-');
                const q = Math.floor((parseInt(month, 10) - 1) / 3) + 1;
                const key = `${year}-Q${q}`;
                if (!map[key]) map[key] = { sortKey: key, label: `Q${q} '${year.slice(2)}`, total: 0 };
                map[key].total += p.totalIssued;
            }
            return Object.values(map)
                .sort((a, b) => a.sortKey.localeCompare(b.sortKey))
                .map(e => ({ label: e.label, value: Math.max(Math.round(e.total / 1_000_000 * 10) / 10, 0.1) }));
        }

        // Yearly
        const map: Record<string, number> = {};
        for (const p of points) {
            const year = p.period.slice(0, 4);
            map[year] = (map[year] ?? 0) + p.totalIssued;
        }
        return Object.entries(map)
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([year, total]) => ({ label: year, value: Math.max(Math.round(total / 1_000_000 * 10) / 10, 0.1) }));
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
        Math.round((dashboardSummary.value?.totalIssued ?? 0) / 1_000_000 * 10) / 10,
    );

    // Convert HCS consensusTimestamp (Unix seconds string) to relative time string
    function timeAgo(timestamp: string | null | undefined): string {
        if (!timestamp) return '';
        const seconds = parseFloat(timestamp);
        const diff = Date.now() / 1000 - seconds;
        if (diff < 60)     return 'just now';
        if (diff < 3600)   return `${Math.round(diff / 60)} min ago`;
        if (diff < 86400)  return `${Math.round(diff / 3600)} hours ago`;
        return `${Math.round(diff / 86400)} days ago`;
    }

    // Real activity feed built from live API data
    const recentActivity = computed<ActivityItem[]>(() => {
        const items: ActivityItem[] = [];

        // New project registered — most recently created project
        const latestProject = recentProjects.value[0];
        if (latestProject) {
            items.push({
                time: timeAgo(latestProject.sourceTimestamp),
                action: 'New project registered',
                detail: `${latestProject.name} — ${latestProject.registry ?? ''}`,
                type: 'project',
            });
        }

        // Policy published — most recently created methodology
        const latestMethodology = recentMethodologiesData.value?.data[0];
        if (latestMethodology) {
            items.push({
                time: timeAgo(latestMethodology.sourceTimestamp ?? undefined),
                action: 'Policy published',
                detail: `${latestMethodology.name} — ${latestMethodology.registryName ?? ''}`,
                type: 'policy',
            });
        }

        // New registry joined — most recently created registry
        const latestRegistry = recentRegistriesData.value?.data[0];
        if (latestRegistry) {
            items.push({
                time: timeAgo(latestRegistry.sourceTimestamp ?? undefined),
                action: 'New registry joined',
                detail: latestRegistry.name ?? latestRegistry.did ?? '',
                type: 'registry',
            });
        }

        // Issuances minted — top 2 most recently issued projects
        const recentIssuances = _realProjects.value
            .filter(p => (p.totalIssued ?? 0) > 0 && p.sourceTimestamp)
            .sort((a, b) => (b.sourceTimestamp ?? '').localeCompare(a.sourceTimestamp ?? ''))
            .slice(0, 2);
        for (const p of recentIssuances) {
            items.push({
                time: timeAgo(p.sourceTimestamp),
                action: 'Issuances minted',
                detail: `${formatCredits(p.totalIssued!)} — ${p.name}`,
                type: 'credit',
            });
        }

        // Sort all items by most recent first
        return items.sort((a, b) => {
            const toSeconds = (t: string) => {
                if (t === 'just now') return 0;
                const minMatch = t.match(/^(\d+) min/);
                if (minMatch) return parseInt(minMatch[1]) * 60;
                const hrMatch = t.match(/^(\d+) hours/);
                if (hrMatch) return parseInt(hrMatch[1]) * 3600;
                const dayMatch = t.match(/^(\d+) days/);
                if (dayMatch) return parseInt(dayMatch[1]) * 86400;
                return 0;
            };
            return toSeconds(a.time) - toSeconds(b.time);
        });
    });


    // Stats active filter flag (still driven by mock filter state)
    const hasActiveFilter = computed(() => {
        if (!filters?.value) return false;
        const f = filters.value;
        return (f.developer && f.developer !== 'All Developers') || (f.registry && f.registry !== 'All Registries');
    });

    // Sector breakdown for pie charts
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
                color: getSectorColor(label),
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

    // -- Real API: full dashboard summary (totals + timeline + registry breakdown) --
    const { data: dashboardSummary } = useDashboardSummaryApi({ network: _network });

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

    // -- Real API: recent projects for activity feed --
    const { projects: recentProjects } = useProjectsApi({
        page: ref(1), limit: ref(5), search: ref(''),
        network: _network, sortBy: ref('createdAt'), sortDir: ref('desc'),
    });

    // -- Real API: recent methodologies for activity feed --
    const { data: recentMethodologiesData } = useMethodologiesApi({
        page: ref(1), limit: ref(3), search: ref(''),
        network: _network, sortBy: ref('createdAt'), sortDir: ref('desc'),
    });

    // -- Real API: recent registries for activity feed --
    const { data: recentRegistriesData } = useRegistriesApi({
        page: ref(1), limit: ref(3), search: ref(''),
        network: _network, sortBy: ref('createdAt'), sortDir: ref('desc'),
    });

    const rawTimeline = computed(() => dashboardSummary.value?.timeline ?? []);

    // -----------------------------------------------------------------------
    // Overrides: use real API data instead of mock-backed computeds
    // -----------------------------------------------------------------------

    // Override stats — use real counts, fall back to 0 when data isn't loaded yet
    const stats = computed(() => {
        const registryCount = registriesCountData.value?.meta.total ?? 0;
        const methodologyCount = methodologiesCountData.value?.meta.total ?? 0;
        const projectCount = projectsCountMeta.value?.total ?? 0;
        const totalCredits = dashboardSummary.value?.totalIssued ?? 0;
        const totalRetiredVal = dashboardSummary.value?.totalRetired ?? 0;
        return {
            registries: registryCount,
            methodologies: methodologyCount,
            projects: projectCount,
            totalCredits,
            totalRetired: totalRetiredVal,
        };
    });

    const totalRetired = computed(() => dashboardSummary.value?.totalRetired ?? 0);

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
        // projectCount — derived from local project batch
        const projectGroups: Record<string, number> = {};
        for (const p of _realProjects.value) {
            const name = p.registry || 'Unknown Registry';
            projectGroups[name] = (projectGroups[name] ?? 0) + 1;
        }

        // creditCount — from API registry breakdown (MintToken VCs, accurate)
        const creditMap: Record<string, number> = {};
        for (const r of dashboardSummary.value?.registryBreakdown ?? []) {
            creditMap[r.registry] = r.totalIssued;
        }

        const allNames = new Set([...Object.keys(projectGroups), ...Object.keys(creditMap)]);
        let fallbackIdx = 0;
        return Array.from(allNames)
            .map(label => ({
                label,
                projectCount: projectGroups[label] ?? 0,
                creditCount: creditMap[label] ?? 0,
                color: registryColors[label] || fallbackColors[fallbackIdx++ % fallbackColors.length],
            }))
            .sort((a, b) => b.projectCount - a.projectCount);
    });

    // Override sectorBreakdown — group real projects by normalized sector
    const sectorBreakdownReal = computed(() => {
        const groups: Record<string, { projectCount: number; creditCount: number }> = {};
        for (const p of _realProjects.value) {
            const label = p.sector || 'Others';
            if (!groups[label]) groups[label] = { projectCount: 0, creditCount: 0 };
            groups[label].projectCount++;
            groups[label].creditCount += p.totalIssued ?? p.credits ?? 0;
        }
        return Object.entries(groups)
            .map(([label, data]) => ({
                label,
                projectCount: data.projectCount,
                creditCount: data.creditCount,
                color: getSectorColor(label),
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
        sectorBreakdown: sectorBreakdownReal,
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

import { DataSource } from 'typeorm';
import { MV_PROJECT_STATS_NAME, MV_REGISTRY_STATS_NAME } from '@shared/materialized-views';

export interface MintAggRow {
    sector: string;
    registry: string;
    month: Date | null;
    amount: string; // Postgres returns BIGINT as string
}

export interface DashboardMintQuery {
    registry?: string;
    developer?: string;
    registryDid?: string;
}

/**
 * Single aggregation query against project_mint_link JOIN business_view.
 *
 * Groups by (sector, registry, month) in one pass — the caller pivots the
 * result into totalMinted / mintSeries / bySector / byRegistry without any
 * extra round trips.
 *
 * Performance notes:
 *  - project_mint_link.project_key has idx_pml_project_key —
 *    the JOIN to business_view hits that index.
 *  - Registry display names are resolved via a non-correlated `DISTINCT ON`
 *    derived table (computed once, over the small ~dozens-of-rows REGISTRY
 *    set) instead of a per-row LATERAL subquery — cost stays flat regardless
 *    of how many project_mint_link rows are being aggregated.
 *  - No per-project loop; the DB engine handles the aggregation in one plan.
 *  - We filter pml.amount > 0 and pml.token_id IS NOT NULL early so the
 *    aggregation only touches real mint rows.
 */
export interface CountryAggRow {
    country: string | null;
    projects: string;
    credits: string;
    methodologies: string;
    developer: string | null;
    registry: string | null;
}

export interface LabelAggRow {
    label: string | null;
    projects: string;
    credits: string;
    methodologies: string;
}

export interface TotalsRow {
    registries: string;
    methodologies: string;
    projects: string;
    /** Distinct registries/methodologies WITHIN the filtered project set — what the stat cards show while a filter is active. */
    filtered_registries: string;
    filtered_methodologies: string;
}

export interface FilterOptionsRow {
    developers: string[] | null;
    registries: string[] | null;
}

/** One developer's leaderboard row, including the distinct-dimension counts shown in the table. */
export interface DeveloperAggRow {
    label: string | null;
    projects: string;
    credits: string;
    country_count: string;
    sector_count: string;
}

/** One (registry, status) cell of the analytics throughput cross-tab. */
export interface RegistryStatusRow {
    registry: string | null;
    status: string | null;
    projects: string;
}

/** Portfolio-level lifecycle volumes and derived averages for the analytics page. */
export interface PortfolioMetricsRow {
    total_issued: string;
    total_retired: string;
    total_active: string;
    avg_vintage_year: string | null;
    avg_crediting_period_years: string | null;
}

/** One (country, label) bucket backing the country detail panel's sector / registry donuts. */
export interface CountryBreakdownRow {
    country: string | null;
    label: string | null;
    projects: string;
    credits: string;
}

export interface MapPointRow {
    name: string | null;
    lat: string | null;
    lng: string | null;
    credits: string | null;
}

export class PgDashboardRepository {
    constructor(private readonly dataSource: DataSource) {}

    /**
     * Shared FROM/WHERE for the per-project aggregates.
     *
     * Issued credits come from `mv_project_stats`, falling back to
     * `businessData->>'credits'` for projects the mint linker hasn't
     * attributed — matching what the project list DTO exposes as `credits`.
     */
    private buildProjectScope(query: DashboardMintQuery): { from: string; where: string; params: unknown[] } {
        const params: unknown[] = [];
        const conditions: string[] = [`bv."viewType" = 'PROJECT'`];

        if (query.registry) {
            params.push(query.registry);
            conditions.push(`reg.registry_name = $${params.length}`);
        }
        if (query.developer) {
            params.push(query.developer);
            conditions.push(`bv."businessData"->>'developer' = $${params.length}`);
        }
        if (query.registryDid) {
            params.push(query.registryDid);
            conditions.push(`bv."registryDid" = $${params.length}`);
        }

        const from = `
            business_view bv
            LEFT JOIN ${MV_REGISTRY_STATS_NAME} reg ON reg."registryDid" = bv."registryDid"
            LEFT JOIN ${MV_PROJECT_STATS_NAME} ps ON ps."projectKey" = bv."projectKey"
        `;

        return { from, where: conditions.join(' AND '), params };
    }

    /** Issued-credit expression shared by every aggregate, so the tiles, country table and breakdowns always agree. */
    private static readonly CREDITS_EXPR = `
        COALESCE(
            ps.total_issued,
            NULLIF(bv."businessData"->>'credits', '')::numeric,
            0
        )
    `;

    /**
     * Deduplicated registry/methodology totals plus the filtered project count.
     *
     * The registry and methodology counts use
     * `COUNT(*) FILTER (key IS NULL) + COUNT(DISTINCT key) FILTER (key IS NOT NULL)`,
     * which reproduces the canonical-row dedup semantics without a correlated
     * subquery. That equivalence holds only because nothing here filters on a
     * row-varying attribute — a filter could match a non-canonical row and the
     * two forms would then disagree, which is why the list endpoints use a
     * `DISTINCT ON` join instead. The registry count applies the same
     * "non-empty registries only" rule as the registries list's hideEmpty.
     */
    async getTotals(query: DashboardMintQuery = {}): Promise<TotalsRow> {
        const scope = this.buildProjectScope(query);

        const sql = `
            SELECT
                (
                    -- mv_registry_stats is already one row per registryDid (canonical),
                    -- so this reads the count directly instead of deduplicating the raw
                    -- REGISTRY population in business_view on every call.
                    SELECT COUNT(*)::bigint
                    FROM mv_registry_stats
                    WHERE COALESCE(policy_count, 0) + COALESCE(project_count, 0)
                        + COALESCE(issuance_count, 0) + COALESCE(user_count, 0) > 0
                )                                                       AS registries,
                (
                    -- mv_methodology_stats is keyed by relatedTopicId (WHERE relatedTopicId
                    -- IS NOT NULL), so it already equals COUNT(DISTINCT relatedTopicId);
                    -- only the relatedTopicId IS NULL standalone rows still need a scan.
                    (SELECT COUNT(*)::bigint FROM business_view
                     WHERE "viewType" = 'METHODOLOGY' AND "relatedTopicId" IS NULL)
                  + (SELECT COUNT(*)::bigint FROM mv_methodology_stats)
                )                                                       AS methodologies,
                agg.projects,
                agg.filtered_registries,
                agg.filtered_methodologies
            FROM (
                SELECT
                    COUNT(*)::bigint                                            AS projects,
                    COUNT(DISTINCT reg.registry_name)::bigint                   AS filtered_registries,
                    COUNT(DISTINCT bv."businessData"->>'methodologyId')::bigint AS filtered_methodologies
                FROM ${scope.from}
                WHERE ${scope.where}
            ) agg
        `;

        const rows: TotalsRow[] = await this.dataSource.query(sql, scope.params);
        return rows[0] ?? {
            registries: '0',
            methodologies: '0',
            projects: '0',
            filtered_registries: '0',
            filtered_methodologies: '0',
        };
    }

    /**
     * Distinct developer / registry labels for the dashboard's filter dropdowns.
     *
     * Ignores the active filters: the dropdowns must keep offering every
     * option, otherwise selecting a developer would collapse the list to that
     * one value and strand the user.
     */
    async getFilterOptions(): Promise<FilterOptionsRow> {
        const sql = `
            SELECT
                ARRAY_AGG(DISTINCT developer) FILTER (WHERE developer <> '')       AS developers,
                ARRAY_AGG(DISTINCT registry_name) FILTER (WHERE registry_name <> '') AS registries
            FROM (
                SELECT
                    COALESCE(bv."businessData"->>'developer', '') AS developer,
                    COALESCE(reg.registry_name, '')               AS registry_name
                FROM business_view bv
                LEFT JOIN ${MV_REGISTRY_STATS_NAME} reg ON reg."registryDid" = bv."registryDid"
                WHERE bv."viewType" = 'PROJECT'
            ) opts
        `;

        const rows: FilterOptionsRow[] = await this.dataSource.query(sql);
        return rows[0] ?? { developers: [], registries: [] };
    }

    /** Per-country project/credit/methodology counts in one GROUP BY. Raw country strings are returned as stored — the client owns ISO-code mapping and "Unknown" bucketing. */
    async getCountryAggregates(query: DashboardMintQuery = {}): Promise<CountryAggRow[]> {
        const scope = this.buildProjectScope(query);

        const sql = `
            SELECT
                bv."businessData"->>'country'                                  AS country,
                COUNT(*)::bigint                                               AS projects,
                COALESCE(SUM(${PgDashboardRepository.CREDITS_EXPR}), 0)::bigint AS credits,
                COUNT(DISTINCT bv."businessData"->>'methodologyId')::bigint    AS methodologies,
                MIN(bv."businessData"->>'developer')                           AS developer,
                MIN(reg.registry_name)                                         AS registry
            FROM ${scope.from}
            WHERE ${scope.where}
            GROUP BY bv."businessData"->>'country'
            ORDER BY projects DESC
        `;

        return this.dataSource.query(sql, scope.params);
    }

    /** Project counts grouped by an arbitrary label expression (registry name, sector, vintage). */
    private async getLabelAggregates(
        labelSql: string,
        query: DashboardMintQuery,
    ): Promise<LabelAggRow[]> {
        const scope = this.buildProjectScope(query);

        const sql = `
            SELECT
                ${labelSql}                                                    AS label,
                COUNT(*)::bigint                                               AS projects,
                COALESCE(SUM(${PgDashboardRepository.CREDITS_EXPR}), 0)::bigint AS credits,
                COUNT(DISTINCT bv."businessData"->>'methodologyId')::bigint    AS methodologies
            FROM ${scope.from}
            WHERE ${scope.where}
            GROUP BY ${labelSql}
            ORDER BY projects DESC
        `;

        return this.dataSource.query(sql, scope.params);
    }

    getRegistryAggregates(query: DashboardMintQuery = {}): Promise<LabelAggRow[]> {
        return this.getLabelAggregates('reg.registry_name', query);
    }

    getSectorAggregates(query: DashboardMintQuery = {}): Promise<LabelAggRow[]> {
        return this.getLabelAggregates(`bv."businessData"->>'sector'`, query);
    }

    getVintageAggregates(query: DashboardMintQuery = {}): Promise<LabelAggRow[]> {
        return this.getLabelAggregates(`bv."businessData"->>'vintage'`, query);
    }

    getStatusAggregates(query: DashboardMintQuery = {}): Promise<LabelAggRow[]> {
        return this.getLabelAggregates(`bv."businessData"->>'status'`, query);
    }

    /**
     * Projects grouped by derived lifecycle stage:
     * Registered -> Validation -> Monitoring -> Verified -> Issued.
     *
     * Reads the stage off mv_project_lifecycle instead of re-deriving it from
     * policy.policyMapping x linkedVcs — that MV already computes this exact
     * classification (see src/shared/materialized-views/project-lifecycle.mv.ts)
     * on the same 60s refresh cadence this endpoint's cache TTL assumes.
     * Re-deriving it live here cost ~520ms per call (EXPLAIN ANALYZE against
     * the testnet dump); joining the MV costs ~7ms.
     */
    async getLifecycleStageAggregates(query: DashboardMintQuery = {}): Promise<LabelAggRow[]> {
        const scope = this.buildProjectScope(query);

        const sql = `
            SELECT
                COALESCE(ml.lifecycle_stage, 'Registered')                    AS label,
                COUNT(*)::bigint                                              AS projects,
                COALESCE(SUM(${PgDashboardRepository.CREDITS_EXPR}), 0)::bigint AS credits,
                COUNT(DISTINCT bv."businessData"->>'methodologyId')::bigint   AS methodologies
            FROM ${scope.from}
            LEFT JOIN mv_project_lifecycle ml ON ml."projectKey" = bv."projectKey"
            WHERE ${scope.where}
            GROUP BY COALESCE(ml.lifecycle_stage, 'Registered')
        `;

        return this.dataSource.query(sql, scope.params);
    }

    getMethodologyAggregates(query: DashboardMintQuery = {}): Promise<LabelAggRow[]> {
        return this.getLabelAggregates(`bv."businessData"->>'methodology'`, query);
    }

    /**
     * Portfolio-level metrics for the analytics page: lifecycle volumes plus the
     * two averages it derives (vintage year, crediting-period length).
     *
     * Computed in one pass in Postgres. The vintage/crediting-period guards
     * mirror the client-side ones exactly — vintage restricted to 2000..2030,
     * crediting periods only counted when both ends parse and end > start —
     * so the displayed averages are unchanged.
     */
    async getPortfolioMetrics(query: DashboardMintQuery = {}): Promise<PortfolioMetricsRow> {
        const scope = this.buildProjectScope(query);

        const sql = `
            SELECT
                COALESCE(SUM(ps.total_issued), 0)::bigint                        AS total_issued,
                COALESCE(SUM(ps.total_retired), 0)::bigint                       AS total_retired,
                COALESCE(SUM(ps.total_issued) - SUM(ps.total_retired), 0)::bigint AS total_active,
                AVG(
                    CASE
                        WHEN (bv."businessData"->>'vintage') ~ '^[0-9]{4}$'
                         AND (bv."businessData"->>'vintage')::int BETWEEN 2000 AND 2030
                        THEN (bv."businessData"->>'vintage')::int
                    END
                )                                                                AS avg_vintage_year,
                AVG(
                    CASE
                        WHEN cp.start_ts IS NOT NULL
                         AND cp.end_ts   IS NOT NULL
                         AND cp.end_ts > cp.start_ts
                        THEN EXTRACT(EPOCH FROM (cp.end_ts - cp.start_ts)) / (60 * 60 * 24 * 365.25)
                    END
                )                                                                AS avg_crediting_period_years
            FROM ${scope.from}
            LEFT JOIN LATERAL (
                -- Dates arrive as free-form strings; a bad value must skip the
                -- row, not abort the whole aggregate, so parse defensively.
                SELECT
                    CASE WHEN (bv."businessData"->>'creditingPeriodStart') ~ '^\\d{4}-\\d{2}-\\d{2}'
                         THEN (left(bv."businessData"->>'creditingPeriodStart', 10))::timestamptz END AS start_ts,
                    CASE WHEN (bv."businessData"->>'creditingPeriodEnd') ~ '^\\d{4}-\\d{2}-\\d{2}'
                         THEN (left(bv."businessData"->>'creditingPeriodEnd', 10))::timestamptz END   AS end_ts
            ) cp ON true
            WHERE ${scope.where}
        `;

        const rows: PortfolioMetricsRow[] = await this.dataSource.query(sql, scope.params);
        return rows[0] ?? {
            total_issued: '0',
            total_retired: '0',
            total_active: '0',
            avg_vintage_year: null,
            avg_crediting_period_years: null,
        };
    }

    /**
     * (country, label) buckets for the country detail panel's donuts.
     *
     * Grouped server-side so clicking a country needs no extra round trip and
     * no per-project data on the client. Bounded by
     * distinct(country) x distinct(label), which stays small.
     */
    private async getCountryBreakdown(
        labelSql: string,
        query: DashboardMintQuery,
    ): Promise<CountryBreakdownRow[]> {
        const scope = this.buildProjectScope(query);

        const sql = `
            SELECT
                bv."businessData"->>'country'                                  AS country,
                ${labelSql}                                                    AS label,
                COUNT(*)::bigint                                               AS projects,
                COALESCE(SUM(${PgDashboardRepository.CREDITS_EXPR}), 0)::bigint AS credits
            FROM ${scope.from}
            WHERE ${scope.where}
            GROUP BY bv."businessData"->>'country', ${labelSql}
        `;

        return this.dataSource.query(sql, scope.params);
    }

    /**
     * Developer leaderboard: per-developer project/credit volume plus the
     * distinct country and sector counts the analytics table shows.
     *
     * The distinct counts are why this needs its own query rather than reusing
     * getLabelAggregates — COUNT(DISTINCT) over two extra dimensions can't be
     * derived from a per-developer row on the client without shipping every
     * project.
     */
    async getDeveloperAggregates(query: DashboardMintQuery = {}): Promise<DeveloperAggRow[]> {
        const scope = this.buildProjectScope(query);

        const sql = `
            SELECT
                bv."businessData"->>'developer'                                 AS label,
                COUNT(*)::bigint                                               AS projects,
                COALESCE(SUM(${PgDashboardRepository.CREDITS_EXPR}), 0)::bigint AS credits,
                COUNT(DISTINCT NULLIF(bv."businessData"->>'country', ''))::bigint AS country_count,
                COUNT(DISTINCT NULLIF(bv."businessData"->>'sector', ''))::bigint  AS sector_count
            FROM ${scope.from}
            WHERE ${scope.where}
            GROUP BY bv."businessData"->>'developer'
            ORDER BY credits DESC
        `;

        return this.dataSource.query(sql, scope.params);
    }

    /**
     * (registry, lifecycle stage) cross-tab for the analytics registry throughput heatmap.
     *
     * Same mv_project_lifecycle join as getLifecycleStageAggregates, for the
     * same reason — re-deriving the stage live here cost ~850ms per call
     * (EXPLAIN ANALYZE against the testnet dump); the MV join costs ~16ms.
     */
    async getRegistryStatusBreakdown(query: DashboardMintQuery = {}): Promise<RegistryStatusRow[]> {
        const scope = this.buildProjectScope(query);

        const sql = `
            SELECT
                reg.registry_name                                          AS registry,
                COALESCE(ml.lifecycle_stage, 'Registered')                  AS status,
                COUNT(*)::bigint                                           AS projects
            FROM ${scope.from}
            LEFT JOIN mv_project_lifecycle ml ON ml."projectKey" = bv."projectKey"
            WHERE ${scope.where}
            GROUP BY reg.registry_name, COALESCE(ml.lifecycle_stage, 'Registered')
        `;

        return this.dataSource.query(sql, scope.params);
    }

    getCountrySectorBreakdown(query: DashboardMintQuery = {}): Promise<CountryBreakdownRow[]> {
        // The detail panel's donut buckets by `category`, not `sector`.
        return this.getCountryBreakdown(`bv."businessData"->>'category'`, query);
    }

    getCountryRegistryBreakdown(query: DashboardMintQuery = {}): Promise<CountryBreakdownRow[]> {
        return this.getCountryBreakdown('reg.registry_name', query);
    }

    /**
     * Map markers for projects that carry coordinates.
     *
     * Filtered to rows that actually have lat/lng, so this returns nothing at
     * all for datasets without geo data instead of streaming every project —
     * which is what the old client-side `fetchAll` + filter did.
     */
    async getMapPoints(query: DashboardMintQuery = {}): Promise<MapPointRow[]> {
        const scope = this.buildProjectScope(query);

        const sql = `
            SELECT
                bv."displayName"                                    AS name,
                bv."businessData"->>'lat'                           AS lat,
                bv."businessData"->>'lng'                           AS lng,
                ${PgDashboardRepository.CREDITS_EXPR}::bigint       AS credits
            FROM ${scope.from}
            WHERE ${scope.where}
              AND (bv."businessData"->>'lat') IS NOT NULL
              AND (bv."businessData"->>'lng') IS NOT NULL
        `;

        return this.dataSource.query(sql, scope.params);
    }

    async getMintAggregations(query: DashboardMintQuery = {}): Promise<MintAggRow[]> {
        const params: unknown[] = [];

        const conditions: string[] = [
            `pml.token_id IS NOT NULL`,
            `pml.amount IS NOT NULL`,
            `pml.amount > 0`,
        ];

        if (query.registry) {
            params.push(query.registry);
            conditions.push(`reg.registry_name = $${params.length}`);
        }

        if (query.developer) {
            params.push(query.developer);
            conditions.push(`bv."businessData"->>'developer' = $${params.length}`);
        }

        const where = conditions.join(' AND ');

        const sql = `
            SELECT
                COALESCE(bv."businessData"->>'sector', '')                   AS sector,
                COALESCE(reg.registry_name, bv."registryDid", 'Unknown')     AS registry,
                DATE_TRUNC('month', pml.mint_date)::date                     AS month,
                SUM(pml.amount)::bigint                                      AS amount
            FROM project_mint_link pml
            JOIN business_view bv
                ON bv."projectKey" = pml.project_key
               AND bv."viewType" = 'PROJECT'
            LEFT JOIN (
                SELECT DISTINCT ON ("registryDid")
                       "registryDid",
                       "displayName" AS registry_name
                FROM business_view
                WHERE "viewType" = 'REGISTRY'
                ORDER BY "registryDid", "createdAt" DESC NULLS LAST
            ) reg ON reg."registryDid" = bv."registryDid"
            WHERE ${where}
            GROUP BY sector, registry, month
            ORDER BY month ASC NULLS LAST
        `;

        return this.dataSource.query(sql, params);
    }
}

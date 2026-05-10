import { DataSource } from 'typeorm';
import { DashboardSummaryDto } from '../dto/summary.dto';

export class PgSummaryRepository {
    constructor(private readonly dataSource: DataSource) {}

    async getDashboardSummary(): Promise<DashboardSummaryDto> {
        const mintsSql = `
            WITH mints AS MATERIALIZED (
                SELECT
                    (documents -> 'credentialSubject' -> 0 ->> 'amount')::numeric AS amount,
                    "consensusTimestamp"::double precision                          AS ts,
                    "consensusTimestamp"                                            AS consensus_ts,
                    documents ->> 'issuer'                                         AS issuer_did
                FROM message
                WHERE type = 'VC-Document'
                  AND documents -> 'credentialSubject' -> 0 ->> 'type' ILIKE '%MintToken%'
            )
            SELECT
                (SELECT COALESCE(SUM(amount), 0)::bigint FROM mints) AS total_issued,
                (
                    SELECT json_agg(t ORDER BY t.period)
                    FROM (
                        SELECT
                            to_char(date_trunc('month', to_timestamp(ts)), 'YYYY-MM') AS period,
                            SUM(amount)::bigint AS total_issued
                        FROM mints
                        GROUP BY 1
                    ) t
                ) AS timeline,
                (
                    SELECT json_agg(r ORDER BY r.total_issued DESC)
                    FROM (
                        SELECT
                            COALESCE(reg.display_name, m.issuer_did, 'Unknown') AS registry,
                            SUM(m.amount)::bigint AS total_issued
                        FROM mints m
                        LEFT JOIN LATERAL (
                            SELECT "displayName" AS display_name
                            FROM business_view
                            WHERE "viewType" = 'REGISTRY'
                              AND "registryDid" = m.issuer_did
                            ORDER BY "createdAt" DESC NULLS LAST
                            LIMIT 1
                        ) reg ON m.issuer_did IS NOT NULL
                        GROUP BY 1
                    ) r
                ) AS registry_breakdown,
                (
                    SELECT json_agg(s ORDER BY s.total_issued DESC)
                    FROM (
                        SELECT
                            COALESCE(NULLIF(proj."businessData" ->> 'sector', ''), 'Others') AS sector,
                            SUM(m.amount)::bigint AS total_issued
                        FROM mints m
                        JOIN project_mint_link pml
                            ON pml.mint_consensus_timestamp = m.consensus_ts
                        JOIN business_view proj
                            ON proj."sourceTimestamp" = pml.project_source_timestamp
                            AND proj."viewType" = 'PROJECT'
                        GROUP BY 1
                    ) s
                ) AS sector_breakdown
        `;

        const retiredSql = `
            SELECT COUNT(*)::bigint AS total_retired
            FROM nft_cache
            WHERE deleted = true
        `;

        const [rows, retiredRows]: [
            Array<{
                total_issued: string;
                timeline: Array<{ period: string; total_issued: string }> | null;
                registry_breakdown: Array<{ registry: string; total_issued: string }> | null;
                sector_breakdown: Array<{ sector: string; total_issued: string }> | null;
            }>,
            Array<{ total_retired: string }>,
        ] = await Promise.all([
            this.dataSource.query(mintsSql),
            this.dataSource.query(retiredSql),
        ]);

        const row = rows[0];
        const totalIssued = parseInt(row?.total_issued ?? '0', 10);
        const totalRetired = parseInt(retiredRows[0]?.total_retired ?? '0', 10);

        return {
            totalIssued,
            totalRetired,
            totalActive: totalIssued - totalRetired,
            timeline: (row?.timeline ?? []).map(t => ({
                period: t.period,
                totalIssued: parseInt(t.total_issued, 10),
            })),
            registryBreakdown: (row?.registry_breakdown ?? []).map(r => ({
                registry: r.registry,
                totalIssued: parseInt(r.total_issued, 10),
            })),
            sectorBreakdown: (row?.sector_breakdown ?? []).map(s => ({
                sector: s.sector,
                totalIssued: parseInt(s.total_issued, 10),
            })),
        };
    }
}

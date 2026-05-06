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
                    documents -> 'credentialSubject' -> 0 ->> 'tokenId'            AS token_id
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
                            COALESCE(bv_reg."displayName", bv_credit."registryDid", 'Unknown') AS registry,
                            SUM(m.amount)::bigint AS total_issued
                        FROM mints m
                        LEFT JOIN business_view bv_credit
                            ON bv_credit."viewType" = 'CREDIT'
                            AND bv_credit."businessData" ->> 'tokenId' = m.token_id
                        LEFT JOIN business_view bv_reg
                            ON bv_reg."viewType" = 'REGISTRY'
                            AND bv_reg."registryDid" = bv_credit."registryDid"
                        GROUP BY 1
                    ) r
                ) AS registry_breakdown
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
        };
    }
}

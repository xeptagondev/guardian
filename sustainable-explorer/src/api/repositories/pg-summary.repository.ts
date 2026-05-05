import { DataSource } from 'typeorm';
import { SummaryResponseDto, TimelinePointDto } from '../dto/summary.dto';

/**
 * Shared CTE: one row per Guardian-issued token, deduplicated via DISTINCT ON.
 *
 * A tokenId can appear in multiple business_view CREDIT rows (each Guardian Token
 * message republication creates a new row).  DISTINCT ON picks the earliest row
 * per token so totalSupply is counted exactly once, consistent across both the
 * summary totals and the timeline breakdown.
 */
const DEDUPED_CREDITS_CTE = `
    deduped AS (
        SELECT DISTINCT ON (tc."tokenId")
            tc."tokenId",
            tc."totalSupply",
            tc.decimals,
            bv."sourceTimestamp" AS first_seen
        FROM business_view bv
        JOIN token_cache tc
            ON tc."tokenId" = bv."businessData" ->> 'tokenId'
        WHERE bv."viewType" = 'CREDIT'
          AND tc."totalSupply" IS NOT NULL
        ORDER BY tc."tokenId", bv."sourceTimestamp" ASC
    )
`;

const ADJUSTED_SUPPLY_EXPR = `
    CASE
        WHEN decimals IS NOT NULL AND decimals > 0
        THEN FLOOR("totalSupply"::numeric / POWER(10, decimals))
        ELSE "totalSupply"::numeric
    END
`;

export class PgSummaryRepository {
    constructor(private readonly dataSource: DataSource) {}

    async getSummary(): Promise<SummaryResponseDto> {
        const issuedSql = `
            WITH ${DEDUPED_CREDITS_CTE}
            SELECT COALESCE(SUM(${ADJUSTED_SUPPLY_EXPR}), 0)::bigint AS total_issued
            FROM deduped
        `;

        const retiredSql = `
            SELECT COUNT(*)::bigint AS total_retired
            FROM nft_cache
            WHERE deleted = true
        `;

        const [issuedRows, retiredRows]: [
            Array<{ total_issued: string }>,
            Array<{ total_retired: string }>,
        ] = await Promise.all([
            this.dataSource.query(issuedSql),
            this.dataSource.query(retiredSql),
        ]);

        const totalIssued = parseInt(issuedRows[0]?.total_issued ?? '0', 10);
        const totalRetired = parseInt(retiredRows[0]?.total_retired ?? '0', 10);
        const totalActive = totalIssued - totalRetired;

        return { totalIssued, totalRetired, totalActive };
    }

    async getTimeline(): Promise<TimelinePointDto[]> {
        const sql = `
            WITH ${DEDUPED_CREDITS_CTE}
            SELECT
                to_char(
                    date_trunc('month', to_timestamp(first_seen::double precision)),
                    'YYYY-MM'
                ) AS period,
                SUM(${ADJUSTED_SUPPLY_EXPR})::bigint AS total_issued
            FROM deduped
            GROUP BY 1
            ORDER BY 1
        `;

        const rows: Array<{ period: string; total_issued: string }> =
            await this.dataSource.query(sql);

        return rows.map(r => ({
            period: r.period,
            totalIssued: parseInt(r.total_issued ?? '0', 10),
        }));
    }
}

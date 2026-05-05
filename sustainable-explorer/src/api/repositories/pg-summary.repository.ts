import { DataSource } from 'typeorm';
import { SummaryResponseDto } from '../dto/summary.dto';

/**
 * PostgreSQL implementation for global credit-total queries.
 *
 * totalIssued  — sum of all MintToken VC amounts from the message table.
 * totalRetired — count of deleted NFT serials from nft_cache.
 * totalActive  — derived: totalIssued - totalRetired.
 *
 * Both queries run concurrently via Promise.all to keep latency minimal.
 */
export class PgSummaryRepository {
    constructor(private readonly dataSource: DataSource) {}

    async getSummary(): Promise<SummaryResponseDto> {
        const issuedSql = `
            SELECT COALESCE(SUM(
                CASE
                    WHEN decimals IS NOT NULL AND decimals > 0
                    THEN FLOOR(CAST("totalSupply" AS NUMERIC) / POWER(10, decimals))
                    ELSE CAST("totalSupply" AS NUMERIC)
                END
            ), 0)::BIGINT AS total_issued
            FROM token_cache
            WHERE "totalSupply" IS NOT NULL
        `;

        const retiredSql = `
            SELECT COUNT(*)::BIGINT AS total_retired
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
}

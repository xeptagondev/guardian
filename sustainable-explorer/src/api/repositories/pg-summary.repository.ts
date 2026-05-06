import { DataSource } from 'typeorm';
import { SummaryResponseDto, TimelinePointDto } from '../dto/summary.dto';

export class PgSummaryRepository {
    constructor(private readonly dataSource: DataSource) {}

    async getSummary(): Promise<SummaryResponseDto> {
        const issuedSql = `
            SELECT COALESCE(
                SUM((m.documents -> 'credentialSubject' -> 0 ->> 'amount')::numeric), 0
            )::bigint AS total_issued
            FROM message m
            WHERE m.type = 'VC-Document'
              AND m.documents -> 'credentialSubject' -> 0 ->> 'type' ILIKE '%MintToken%'
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
            SELECT
                to_char(
                    date_trunc('month', to_timestamp(m."consensusTimestamp"::double precision)),
                    'YYYY-MM'
                ) AS period,
                SUM((m.documents -> 'credentialSubject' -> 0 ->> 'amount')::numeric)::bigint AS total_issued
            FROM message m
            WHERE m.type = 'VC-Document'
              AND m.documents -> 'credentialSubject' -> 0 ->> 'type' ILIKE '%MintToken%'
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

import { DataSource } from 'typeorm';
import {
    IssuanceRepository,
    IssuanceListQuery,
    IssuanceListResult,
    IssuanceListRow,
} from './issuance.repository';

// COALESCE expressions used in both SELECT and ORDER BY / WHERE
const TOKEN_ID_EXPR = `COALESCE(pml.token_id, m.documents -> 'credentialSubject' -> 0 ->> 'tokenId')`;
const AMOUNT_EXPR = `COALESCE(pml.amount, (m.documents -> 'credentialSubject' -> 0 ->> 'amount')::numeric)`;
const MINT_DATE_EXPR = `COALESCE(pml.mint_date::date, to_timestamp(m."consensusTimestamp"::double precision)::date)`;

const SORT_COLUMN_MAP: Record<string, string> = {
    mintDate: MINT_DATE_EXPR,
    amount: AMOUNT_EXPR,
    projectName: `proj."displayName"`,
    tokenId: TOKEN_ID_EXPR,
};

const BASE_FROM = `
    FROM message m
    LEFT JOIN project_mint_link pml ON pml.mint_consensus_timestamp = m."consensusTimestamp"
    LEFT JOIN business_view proj
        ON proj."sourceTimestamp" = pml.project_source_timestamp
        AND proj."viewType" = 'PROJECT'
    LEFT JOIN LATERAL (
        SELECT "displayName" AS registry_name
        FROM business_view
        WHERE "viewType" = 'REGISTRY'
          AND "registryDid" = proj."registryDid"
        ORDER BY "createdAt" DESC NULLS LAST
        LIMIT 1
    ) reg ON true
    LEFT JOIN token_cache tc ON tc."tokenId" = ${TOKEN_ID_EXPR}
`;

export class PgIssuanceRepository extends IssuanceRepository {
    constructor(private readonly dataSource: DataSource) {
        super();
    }

    async findAll(query: IssuanceListQuery): Promise<IssuanceListResult> {
        const { page, limit, search, sortBy, sortDir, dateFrom, dateTo, tokenType, projectId } = query;
        const offset = (page - 1) * limit;

        const params: unknown[] = [];
        const whereClauses: string[] = [
            `m.type = 'VC-Document'`,
            `m.documents -> 'credentialSubject' -> 0 ->> 'type' ILIKE '%MintToken%'`,
        ];

        const addParam = (value: unknown): string => {
            params.push(value);
            return `$${params.length}`;
        };

        if (dateFrom) {
            whereClauses.push(`${MINT_DATE_EXPR} >= ${addParam(dateFrom)}::date`);
        }
        if (dateTo) {
            whereClauses.push(`${MINT_DATE_EXPR} <= ${addParam(dateTo)}::date`);
        }
        if (tokenType) {
            whereClauses.push(`tc.type = ${addParam(tokenType)}`);
        }
        if (projectId) {
            whereClauses.push(`pml.project_source_timestamp = ${addParam(projectId)}`);
        }
        if (search) {
            const like = `%${search.trim()}%`;
            whereClauses.push(
                `(proj."displayName" ILIKE ${addParam(like)} OR tc.name ILIKE ${addParam(like)} OR ${TOKEN_ID_EXPR} ILIKE ${addParam(like)})`,
            );
        }

        const whereClause = `WHERE ${whereClauses.join(' AND ')}`;

        const sortExpr = SORT_COLUMN_MAP[sortBy ?? ''] ?? MINT_DATE_EXPR;
        const dir = sortDir === 'asc' ? 'ASC' : 'DESC';
        const orderBy = `${sortExpr} ${dir} NULLS LAST, m."consensusTimestamp" DESC`;

        const limitParam = addParam(limit);
        const offsetParam = addParam(offset);

        const rowsSql = `
            SELECT
                m."consensusTimestamp"                              AS mint_consensus_timestamp,
                ${TOKEN_ID_EXPR}                                    AS token_id,
                ${AMOUNT_EXPR}                                      AS amount,
                ${MINT_DATE_EXPR}                                   AS mint_date,
                pml.link_method,
                pml.project_source_timestamp                        AS project_id,
                proj."displayName"                                  AS project_name,
                proj."businessData" ->> 'methodology'               AS methodology,
                proj."businessData" ->> 'methodologyId'             AS methodology_id,
                proj."businessData" ->> 'country'                   AS country,
                reg.registry_name,
                tc.name                                             AS token_name,
                tc.symbol,
                tc.type                                             AS token_type
            ${BASE_FROM}
            ${whereClause}
            ORDER BY ${orderBy}
            LIMIT ${limitParam} OFFSET ${offsetParam}
        `;

        const countParams = params.slice(0, params.length - 2);
        const countSql = `SELECT COUNT(*)::int AS total ${BASE_FROM} ${whereClause}`;

        const [rawRows, countResult]: [
            Array<Record<string, unknown>>,
            Array<{ total: number }>,
        ] = await Promise.all([
            this.dataSource.query(rowsSql, params),
            this.dataSource.query(countSql, countParams),
        ]);

        return {
            rows: rawRows.map(r => PgIssuanceRepository.mapRow(r)),
            total: countResult[0]?.total ?? 0,
        };
    }

    private static mapRow(r: Record<string, unknown>): IssuanceListRow {
        const mintDate = r['mint_date'];
        let mintDateStr: string | null = null;
        if (mintDate instanceof Date) {
            mintDateStr = mintDate.toISOString().split('T')[0];
        } else if (typeof mintDate === 'string' && mintDate) {
            mintDateStr = mintDate.split('T')[0];
        }

        return {
            mintConsensusTimestamp: String(r['mint_consensus_timestamp'] ?? ''),
            tokenId: r['token_id'] != null ? String(r['token_id']) : null,
            tokenName: r['token_name'] != null ? String(r['token_name']) : null,
            symbol: r['symbol'] != null ? String(r['symbol']) : null,
            tokenType: r['token_type'] != null ? String(r['token_type']) : null,
            amount: r['amount'] != null ? Number(r['amount']) : 0,
            mintDate: mintDateStr,
            projectId: r['project_id'] != null ? String(r['project_id']) : null,
            projectName: r['project_name'] != null ? String(r['project_name']) : null,
            methodology: r['methodology'] != null ? String(r['methodology']) : null,
            methodologyId: r['methodology_id'] != null ? String(r['methodology_id']) : null,
            country: r['country'] != null ? String(r['country']) : null,
            registry: r['registry_name'] != null ? String(r['registry_name']) : null,
            linkMethod: r['link_method'] != null ? String(r['link_method']) : 'unlinked',
        };
    }
}

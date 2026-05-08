import { DataSource } from 'typeorm';
import { MV_METHODOLOGY_STATS_NAME } from '@shared/materialized-views';
import { TokenType } from '@shared/enums/guardian.enums';
import {
    MethodologyRepository,
    MethodologyListQuery,
    MethodologyListResult,
    MethodologyRow,
    MethodologyStatsRow,
    IssuanceRow,
} from './methodology.repository';
import { QueryBuilder } from './query-builder';
import { METHODOLOGY_FIELD_SCHEMA } from './schemas/methodology.schema';

interface RawRow {
    id: string;
    viewType: string;
    sourceTimestamp: string;
    registryDid: string | null;
    relatedTopicId: string | null;
    displayName: string | null;
    businessData: Record<string, any> | null;
    searchText: string | null;
    lastUpdate: string;
    createdAt: Date;
    updatedAt: Date;
    project_count: string | null;
    issuance_count: string | null;
    schema_count: string | null;
    registry_name: string | null;
}

/**
 * LATERAL subquery joined into both findAll and findById to look up the
 * publishing registry's display name. Uses LATERAL so we can ORDER BY +
 * LIMIT 1 to handle the (rare) case of multiple REGISTRY rows for one DID.
 */
const REGISTRY_NAME_JOIN = `
    LEFT JOIN LATERAL (
        SELECT "displayName" AS registry_name
        FROM business_view
        WHERE "viewType" = 'REGISTRY'
          AND "registryDid" = bv."registryDid"
        ORDER BY "createdAt" DESC NULLS LAST
        LIMIT 1
    ) reg ON true
`;

/**
 * PostgreSQL implementation of the MethodologyRepository.
 *
 * Generic filter and sort logic is delegated to QueryBuilder + the field
 * schema (METHODOLOGY_FIELD_SCHEMA). Adding a new filterable/sortable
 * column only requires updating the schema — no SQL changes needed here.
 *
 * Special operations (full-text + fuzzy search, materialized view joins,
 * search ranking) remain explicit because they don't fit the generic
 * operator model.
 */
export class PgMethodologyRepository extends MethodologyRepository {
    constructor(private readonly dataSource: DataSource) {
        super();
    }

    async findAll(query: MethodologyListQuery): Promise<MethodologyListResult> {
        const { page, limit, search, sortBy, sortDir } = query;
        const offset = (page - 1) * limit;

        const builder = new QueryBuilder(METHODOLOGY_FIELD_SCHEMA);
        builder.addClause(`bv."viewType" = 'METHODOLOGY'`);

        // Generic filters: every filterable field defined in the schema
        // is wired automatically. To add a new filter, edit methodology.schema.ts.
        builder.addFilters({
            name: query.name,
            id: query.id,
            description: query.description,
            status: query.status,
            registryDid: query.registryDid,
            registryName: query.registryName,
            version: query.version,
            policyTopicId: query.policyTopicId,
        });

        // Special: full-text search with ranking. The tsvector index covers
        // displayName (weight A), registryDid (B), and searchText (C).
        // ILIKE on displayName is kept as a fast prefix fallback for partial
        // word matches that tsquery doesn't catch.
        // similarity() provides typo-tolerance via pg_trgm.
        let rankExpr = '0';
        if (search) {
            const term = search.trim();
            const tsParam = builder.nextParam(term);
            const likeParam = builder.nextParam(`%${term}%`);
            const simParam = builder.nextParam(term);

            builder.addClause(`(
                bv."searchVector" @@ plainto_tsquery('english', ${tsParam})
                OR bv."displayName" ILIKE ${likeParam}
                OR bv."registryDid" ILIKE ${likeParam}
                OR similarity(COALESCE(bv."displayName", ''), ${simParam}) > 0.3
            )`);

            rankExpr = `
                ts_rank(bv."searchVector", plainto_tsquery('english', ${tsParam}))
                + COALESCE(similarity(bv."displayName", ${simParam}), 0)
            `;
        }

        // ORDER BY: search results rank by relevance; otherwise use schema sort
        const orderBy = search
            ? `search_rank DESC, bv."createdAt" DESC`
            : builder.buildOrderBy({
                sortBy,
                sortDir,
                defaultExpr: 'bv."createdAt" DESC NULLS LAST',
            });

        const whereSql = builder.getWhereClause();
        const params = builder.getParams();

        // Append LIMIT/OFFSET as the last two params
        const limitParam = builder.nextParam(limit);
        const offsetParam = builder.nextParam(offset);

        const rowsSql = `
            SELECT
                bv.*,
                s.project_count,
                s.issuance_count,
                s.schema_count,
                reg.registry_name,
                ${rankExpr} AS search_rank
            FROM business_view bv
            LEFT JOIN ${MV_METHODOLOGY_STATS_NAME} s
                ON s."relatedTopicId" = bv."relatedTopicId"
            ${REGISTRY_NAME_JOIN}
            WHERE ${whereSql}
            ORDER BY ${orderBy}
            LIMIT ${limitParam} OFFSET ${offsetParam}
        `;

        // Count query reuses the same WHERE and LATERAL join (so filters that
        // reference `reg.registry_name` resolve correctly), but skips the stats
        // MV join and the LIMIT/OFFSET params.
        const countParams = params.slice(0, params.length - 2);
        const countSql = `
            SELECT COUNT(*)::int AS total
            FROM business_view bv
            ${REGISTRY_NAME_JOIN}
            WHERE ${whereSql}
        `;

        const [rawRows, countResult]: [RawRow[], Array<{ total: number }>] = await Promise.all([
            this.dataSource.query(rowsSql, params),
            this.dataSource.query(countSql, countParams),
        ]);

        return {
            rows: rawRows.map(row => PgMethodologyRepository.mapRow(row)),
            total: countResult[0]?.total ?? 0,
        };
    }

    async findById(id: string): Promise<MethodologyRow | null> {
        const rawRows: RawRow[] = await this.dataSource.query(
            `
            SELECT
                bv.*,
                s.project_count,
                s.issuance_count,
                s.schema_count,
                reg.registry_name
            FROM business_view bv
            LEFT JOIN ${MV_METHODOLOGY_STATS_NAME} s
                ON s."relatedTopicId" = bv."relatedTopicId"
            ${REGISTRY_NAME_JOIN}
            WHERE bv."viewType" = 'METHODOLOGY'
              AND bv."relatedTopicId" = $1
            ORDER BY bv."createdAt" DESC NULLS LAST
            LIMIT 1
            `,
            [id],
        );

        if (rawRows.length === 0) return null;

        const row = rawRows[0];

        const policyTopicId = (row.businessData as Record<string, any> | null)?.['topicId'] as string | null;
        const instanceTopicId = row.relatedTopicId;

        // Expand topic search to include all project instance topics under this methodology
        // so MintToken VCs on project sub-topics are captured alongside those on the
        // methodology's own instance topic.
        const projectTopicRows: Array<{ relatedTopicId: string }> = policyTopicId
            ? await this.dataSource.query(
                `SELECT DISTINCT "relatedTopicId"
                 FROM business_view
                 WHERE "viewType" = 'PROJECT'
                   AND "businessData"->>'policyTopicId' = $1
                   AND "relatedTopicId" IS NOT NULL`,
                [policyTopicId],
            )
            : [];

        const topicIds = [
            ...new Set([
                policyTopicId,
                instanceTopicId,
                ...projectTopicRows.map(r => r.relatedTopicId),
            ].filter((t): t is string => !!t)),
        ];

        let issuances: IssuanceRow[] = [];
        if (topicIds.length > 0) {
            const mintTokenRows: Array<{
                token_id: string | null;
                amount: string | null;
                mint_date: string | null;
                documents: Record<string, any> | null;
            }> = await this.dataSource.query(
                `SELECT
                    m.documents -> 'credentialSubject' -> 0 ->> 'tokenId' AS token_id,
                    m.documents -> 'credentialSubject' -> 0 ->> 'amount'  AS amount,
                    m.documents -> 'credentialSubject' -> 0 ->> 'date'    AS mint_date,
                    m.documents
                 FROM message m
                 WHERE m."topicId" = ANY($1::varchar[])
                   AND m.type = 'VC-Document'
                   AND m.documents -> 'credentialSubject' -> 0 ->> 'type' ILIKE '%MintToken%'
                 ORDER BY m."consensusTimestamp" ASC`,
                [topicIds],
            );

            if (mintTokenRows.length > 0) {
                const mintsByToken = new Map<string, { total: number; mintDate: string | null; rawVc: Record<string, any> | null }>();
                for (const r of mintTokenRows) {
                    if (!r.token_id) continue;
                    const existing = mintsByToken.get(r.token_id) ?? { total: 0, mintDate: r.mint_date, rawVc: r.documents };
                    existing.total += r.amount != null ? Number(r.amount) : 0;
                    existing.rawVc = r.documents;
                    mintsByToken.set(r.token_id, existing);
                }

                const distinctTokenIds = Array.from(mintsByToken.keys());
                const tokenMeta: Array<{ tokenId: string; name: string | null; symbol: string | null; type: string | null }> =
                    await this.dataSource.query(
                        `SELECT "tokenId", name, symbol, type
                         FROM token_cache
                         WHERE "tokenId" = ANY($1::varchar[])`,
                        [distinctTokenIds],
                    );
                const metaMap = new Map(tokenMeta.map(t => [t.tokenId, t]));

                issuances = [...mintsByToken.entries()].map(([tokenId, data]) => {
                    const meta = metaMap.get(tokenId);
                    return {
                        tokenId,
                        name: meta?.name ?? null,
                        symbol: meta?.symbol ?? null,
                        type: meta?.type ?? null,
                        supply: data.total,
                        mintDate: data.mintDate ? new Date(data.mintDate).toISOString().split('T')[0] : null,
                        rawVc: data.rawVc,
                    };
                });
            }
        }

        // Aggregate lifecycle stats for NFT tokens: total minted (all serials) and
        // total retired (serials marked deleted by Mirror Node).
        // Fungible tokens don't have per-serial tracking so their supply is used as-is.
        const nftTokenIds = issuances
            .filter(i => i.type === TokenType.NonFungibleUnique)
            .map(i => i.tokenId)
            .filter((id): id is string => !!id);

        let totalIssued = 0;
        let totalRetired = 0;

        if (nftTokenIds.length > 0) {
            const nftStats: Array<{ tokenId: string; total_minted: string; total_retired: string }> =
                await this.dataSource.query(
                    `SELECT
                        "tokenId",
                        COUNT(*)::text                              AS total_minted,
                        COUNT(*) FILTER (WHERE deleted = true)::text AS total_retired
                     FROM nft_cache
                     WHERE "tokenId" = ANY($1::varchar[])
                     GROUP BY "tokenId"`,
                    [nftTokenIds],
                );

            const nftStatMap = new Map(nftStats.map(s => [s.tokenId, s]));

            for (const s of nftStats) {
                totalIssued += parseInt(s.total_minted, 10);
                totalRetired += parseInt(s.total_retired, 10);
            }

            // nft_cache is ground truth for NFT supply — overwrite VC-derived supply
            // which can be incomplete when mints occurred on sub-topics not searched.
            for (const issuance of issuances) {
                if (issuance.type === TokenType.NonFungibleUnique) {
                    const stat = nftStatMap.get(issuance.tokenId);
                    if (stat) issuance.supply = parseInt(stat.total_minted, 10);
                }
            }
        }

        // Add fungible token supply to totalIssued (retirement not tracked for fungible)
        for (const i of issuances) {
            if (i.type !== TokenType.NonFungibleUnique) {
                totalIssued += i.supply;
            }
        }

        const totalActive = totalIssued - totalRetired;

        return PgMethodologyRepository.mapRow(row, issuances, { totalIssued, totalRetired, totalActive });
    }

    private static mapRow(
        row: RawRow,
        issuances?: IssuanceRow[],
        lifecycle?: { totalIssued: number; totalRetired: number; totalActive: number },
    ): MethodologyRow {
        const stats: MethodologyStatsRow = {
            projectCount: parseInt(row.project_count || '0', 10),
            issuanceCount: parseInt(row.issuance_count || '0', 10),
            schemaCount: parseInt(row.schema_count || '0', 10),
        };

        const data = row.businessData || {};
        const description = typeof data.description === 'string' ? data.description : null;
        const statusValue = typeof data.status === 'string' ? data.status : null;
        const sectoralScopes = Array.isArray(data.sectoralScopes) ? (data.sectoralScopes as string[]) : null;
        const emissionReductionApproach = typeof data.emissionReductionApproach === 'string' ? data.emissionReductionApproach : null;

        return {
            id: row.id,
            viewType: row.viewType,
            sourceTimestamp: row.sourceTimestamp,
            registryDid: row.registryDid,
            registryName: row.registry_name,
            relatedTopicId: row.relatedTopicId,
            displayName: row.displayName,
            description,
            statusValue,
            sectoralScopes,
            emissionReductionApproach,
            businessData: row.businessData,
            searchText: row.searchText,
            lastUpdate: row.lastUpdate,
            createdAt: row.createdAt,
            updatedAt: row.updatedAt,
            stats,
            issuances,
            totalIssued: lifecycle?.totalIssued,
            totalRetired: lifecycle?.totalRetired,
            totalActive: lifecycle?.totalActive,
        };
    }
}

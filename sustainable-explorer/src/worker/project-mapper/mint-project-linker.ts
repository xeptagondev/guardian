import { Logger } from '@nestjs/common';
import { DataSource } from 'typeorm';

/**
 * Ensures the project_mint_link table exists.
 * Called once from BusinessViewBuilderProcessor.onModuleInit().
 */
export async function ensureMintProjectLinkTable(dataSource: DataSource): Promise<void> {
    await dataSource.query(`
        CREATE TABLE IF NOT EXISTS project_mint_link (
            mint_consensus_timestamp varchar(30)  PRIMARY KEY,
            project_source_timestamp varchar(30)  NOT NULL,
            project_topic_id         varchar(20)  NOT NULL,
            token_id                 varchar(20),
            amount                   bigint,
            mint_date                timestamptz,
            link_method              varchar(20)  NOT NULL DEFAULT 'topic_scope'
        );
        CREATE INDEX IF NOT EXISTS idx_pml_project_src
            ON project_mint_link (project_source_timestamp);
        CREATE INDEX IF NOT EXISTS idx_pml_token_id
            ON project_mint_link (token_id);
    `);
}

/**
 * Resolves each unlinked MintToken VC to its specific project and upserts
 * the result into project_mint_link.
 *
 * Called directly from BusinessViewBuilderProcessor after project views are
 * built — no separate queue needed, the whole run takes a few seconds.
 *
 * Resolution strategy:
 *   1. Walk options.relationships recursively (up to 15 hops) until an
 *      ancestor consensusTimestamp matches a business_view PROJECT row.
 *      Using sourceTimestamp as the project key correctly splits grouped
 *      projects (multiple project VCs sharing one instance topic).
 *   2. Fallback to topic-scope only when the instance topic has exactly one
 *      project. Grouped topics without a resolved chain are skipped.
 */
export async function buildMintProjectLinks(
    dataSource: DataSource,
    logger: Logger,
): Promise<void> {
    const unlinked: Array<{
        consensusTimestamp: string;
        topicId: string;
        token_id: string | null;
        amount: string | null;
        mint_date: string | null;
    }> = await dataSource.query(`
        SELECT
            m."consensusTimestamp",
            m."topicId",
            m.documents->'credentialSubject'->0->>'tokenId' AS token_id,
            m.documents->'credentialSubject'->0->>'amount'  AS amount,
            m.documents->'credentialSubject'->0->>'date'    AS mint_date
        FROM message m
        WHERE m.type = 'VC-Document'
          AND m.documents->'credentialSubject'->0->>'type' ILIKE '%MintToken%'
          AND NOT EXISTS (
              SELECT 1 FROM project_mint_link pml
              WHERE pml.mint_consensus_timestamp = m."consensusTimestamp"
          )
        ORDER BY m."consensusTimestamp"
    `);

    if (unlinked.length === 0) return;

    logger.log(`MintProjectLinker: linking ${unlinked.length} new mint(s)`);

    let linked = 0;
    let fallback = 0;
    let skipped = 0;

    for (const mint of unlinked) {
        // Step 1 — relationship chain traversal
        const chainRows: Array<{ project_source_timestamp: string; project_topic_id: string }> =
            await dataSource.query(`
                WITH RECURSIVE rel_chain(ts, depth) AS (
                    SELECT
                        jsonb_array_elements_text(m.options->'relationships')::varchar AS ts,
                        1 AS depth
                    FROM message m
                    WHERE m."consensusTimestamp" = $1
                      AND m.options->'relationships' IS NOT NULL
                      AND jsonb_typeof(m.options->'relationships') = 'array'
                      AND jsonb_array_length(m.options->'relationships') > 0

                    UNION ALL

                    SELECT
                        jsonb_array_elements_text(p.options->'relationships')::varchar,
                        rc.depth + 1
                    FROM rel_chain rc
                    JOIN message p ON p."consensusTimestamp" = rc.ts
                    WHERE rc.depth < 15
                      AND p.options->'relationships' IS NOT NULL
                      AND p.options->'relationships' != 'null'::jsonb
                      AND jsonb_typeof(p.options->'relationships') = 'array'
                )
                SELECT
                    bv."sourceTimestamp"  AS project_source_timestamp,
                    bv."relatedTopicId"   AS project_topic_id
                FROM rel_chain rc
                JOIN business_view bv
                    ON bv."sourceTimestamp" = rc.ts
                   AND bv."viewType" = 'PROJECT'
                ORDER BY rc.depth ASC
                LIMIT 1
            `, [mint.consensusTimestamp]);

        let projectSourceTs: string;
        let projectTopicId: string;
        let linkMethod: string;

        if (chainRows.length > 0) {
            projectSourceTs = chainRows[0].project_source_timestamp;
            projectTopicId = chainRows[0].project_topic_id;
            linkMethod = 'relationship';
            linked++;
        } else {
            // Step 2 — topic-scope fallback (only for unambiguous single-project topics)
            const fallbackRows: Array<{ sourceTimestamp: string; relatedTopicId: string }> =
                await dataSource.query(`
                    SELECT "sourceTimestamp", "relatedTopicId"
                    FROM business_view
                    WHERE "viewType" = 'PROJECT'
                      AND "relatedTopicId" = $1
                `, [mint.topicId]);

            if (fallbackRows.length !== 1) {
                if (fallbackRows.length > 1) {
                    logger.warn(
                        `MintToken ${mint.consensusTimestamp}: grouped topic ${mint.topicId} — ` +
                        `chain unresolved, skipping to avoid misattribution`,
                    );
                }
                skipped++;
                continue;
            }

            projectSourceTs = fallbackRows[0].sourceTimestamp;
            projectTopicId = fallbackRows[0].relatedTopicId;
            linkMethod = 'topic_scope';
            fallback++;
        }

        const amount = mint.amount != null ? Math.round(parseFloat(mint.amount)) : null;
        const mintDate = mint.mint_date ? new Date(mint.mint_date) : null;

        await dataSource.query(`
            INSERT INTO project_mint_link (
                mint_consensus_timestamp,
                project_source_timestamp,
                project_topic_id,
                token_id,
                amount,
                mint_date,
                link_method
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (mint_consensus_timestamp) DO UPDATE SET
                project_source_timestamp = EXCLUDED.project_source_timestamp,
                project_topic_id         = EXCLUDED.project_topic_id,
                token_id                 = EXCLUDED.token_id,
                amount                   = EXCLUDED.amount,
                mint_date                = EXCLUDED.mint_date,
                link_method              = EXCLUDED.link_method
        `, [mint.consensusTimestamp, projectSourceTs, projectTopicId, mint.token_id, amount, mintDate, linkMethod]);
    }

    logger.log(
        `MintProjectLinker: ${linked} via relationship, ${fallback} via topic-scope, ${skipped} skipped`,
    );
}

/**
 * Materialized view: mv_methodology_stats
 *
 * Aggregates per-methodology counts of projects, issuances, and schemas.
 * Each network lives in its own database, so network is NOT part of the key.
 * Keyed by relatedTopicId (the methodology / policy topic ID).
 *
 * Counts:
 *   - project_count   = DYNAMIC_TOPICs hanging off any DECODED policy version
 *                       for this methodology's policy topic. Each project
 *                       registration in Guardian creates one DYNAMIC_TOPIC.
 *   - issuance_count  = Token messages emitted on the policy topic.
 *   - schema_count    = distinct schemaIds extracted from policy_schema.
 *
 * Refreshed periodically by MvRefreshProcessor.
 */
export const MV_METHODOLOGY_STATS_NAME = 'mv_methodology_stats';

export const MV_METHODOLOGY_STATS_CREATE_SQL = `
    CREATE MATERIALIZED VIEW IF NOT EXISTS ${MV_METHODOLOGY_STATS_NAME} AS
    WITH methodology_base AS (
        SELECT
            "relatedTopicId",
            MAX("businessData"->>'topicId') AS policy_topic_id,
            MAX("lastUpdate") AS last_update
        FROM business_view
        WHERE "viewType" = 'METHODOLOGY'
          AND "relatedTopicId" IS NOT NULL
        GROUP BY "relatedTopicId"
    )
    SELECT
        mb."relatedTopicId",
        -- Authoritative source: the project table (one row per extracted
        -- project VC). Aggregates across all DECODED versions of this policy
        -- so a methodology's count covers its full publish history.
        COALESCE((
            SELECT COUNT(*)
            FROM project pr
            JOIN policy p
              ON p."instanceTopicId" = pr."instanceTopicId"
             AND p.status = 'DECODED'
            WHERE p."policyTopicId" = mb.policy_topic_id
        ), 0)::bigint AS project_count,
        COALESCE((
            SELECT COUNT(*)
            FROM message m
            WHERE m."topicId" = mb.policy_topic_id
              AND m.type = 'Token'
              AND m.options->>'tokenId' IS NOT NULL
        ), 0)::bigint AS issuance_count,
        COALESCE((
            SELECT COUNT(DISTINCT ps."schemaId")
            FROM policy_schema ps
            WHERE ps."policyTopicId" = mb.policy_topic_id
        ), 0)::bigint AS schema_count,
        mb.last_update
    FROM methodology_base mb;
`;

// Unique index required for REFRESH MATERIALIZED VIEW CONCURRENTLY
export const MV_METHODOLOGY_STATS_INDEX_SQL = `
    CREATE UNIQUE INDEX IF NOT EXISTS idx_${MV_METHODOLOGY_STATS_NAME}_related_topic_id
    ON ${MV_METHODOLOGY_STATS_NAME} ("relatedTopicId");
`;

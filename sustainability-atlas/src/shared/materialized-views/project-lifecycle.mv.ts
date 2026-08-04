/**
 * Materialized view: mv_project_lifecycle
 *
 * Pre-computes, per PROJECT row, whether it has reached each lifecycle
 * milestone (validation / monitoring / verification / issuance). Previously
 * this was derived live, and independently, inside both
 * PgDashboardRepository.getLifecycleStageAggregates and
 * .getRegistryStatusBreakdown via a LATERAL jsonb_array_elements over
 * businessData.linkedVcs cross-joined against the policy schema's document
 * types — the same unnest-and-classify work run twice on every dashboard
 * cache miss. This MV runs it once per refresh cycle instead.
 *
 * Keyed by business_view.id (row_id), NOT projectKey — projectKey is
 * nullable on PROJECT rows (see idx_business_view_project_key's partial
 * WHERE), and keying on the row's own primary key guarantees a match for
 * every PROJECT row regardless of mint-linker attribution state. Consumers
 * LEFT JOIN on row_id and COALESCE the flags to false, so a project inserted
 * after the last refresh (not yet present here) reads as "Registered" until
 * the next cycle — the same staleness tolerance the rest of the dashboard
 * already accepts via MV_REFRESH_INTERVAL / the 60s response cache.
 *
 * Each network lives in its own database, so network is NOT part of the key.
 *
 * Refreshed periodically by MvRefreshProcessor.
 */
export const MV_PROJECT_LIFECYCLE_NAME = 'mv_project_lifecycle';

export const MV_PROJECT_LIFECYCLE_CREATE_SQL = `
    CREATE MATERIALIZED VIEW IF NOT EXISTS ${MV_PROJECT_LIFECYCLE_NAME} AS
    WITH schema_doc_types AS (
        -- Document type per (policy topic, bare schema UUID). policyMapping
        -- carries full IRIs of the form '#<uuid>&<version>' while a project's
        -- linkedVcs entries carry only the uuid, so the IRI is trimmed to make
        -- the two joinable. Mirrors PgDashboardRepository.SCHEMA_DOC_TYPES_SQL.
        SELECT DISTINCT
            p."policyTopicId"                                    AS policy_topic_id,
            split_part(ltrim(e->>'schemaIri', '#'), '&', 1)      AS schema_uuid,
            e->>'docType'                                        AS doc_type
        FROM policy p,
             LATERAL jsonb_each(COALESCE(p."policyMapping", '{}'::jsonb)) AS kv(k, v),
             LATERAL jsonb_array_elements(
                 CASE WHEN jsonb_typeof(kv.v) = 'array' THEN kv.v ELSE '[]'::jsonb END
             ) AS e
        WHERE p."decodeStatus" = 'decoded'
          AND e ? 'schemaIri'
          AND e ? 'docType'
    )
    SELECT
        bv.id                                                     AS row_id,
        COALESCE(ps.total_issued, 0) > 0
            OR COALESCE(ps.issuance_count, 0) > 0                  AS issued,
        bool_or(sdt.doc_type = 'verificationReport')               AS has_verification,
        bool_or(sdt.doc_type = 'monitoringReport')                 AS has_monitoring,
        bool_or(sdt.doc_type = 'validationReport')                 AS has_validation
    FROM business_view bv
    LEFT JOIN mv_project_stats ps ON ps."projectKey" = bv."projectKey"
    LEFT JOIN LATERAL jsonb_array_elements(
        COALESCE(bv."businessData"->'linkedVcs', '[]'::jsonb)
    ) AS lv ON true
    LEFT JOIN schema_doc_types sdt
        ON sdt.policy_topic_id = bv."businessData"->>'policyTopicId'
       AND sdt.schema_uuid     = lv->>'schemaUuid'
    WHERE bv."viewType" = 'PROJECT'
    GROUP BY bv.id, ps.total_issued, ps.issuance_count;
`;

// Unique index required for REFRESH MATERIALIZED VIEW CONCURRENTLY.
// row_id is business_view's primary key, so it is always unique and non-null.
export const MV_PROJECT_LIFECYCLE_INDEX_SQL = `
    CREATE UNIQUE INDEX IF NOT EXISTS idx_${MV_PROJECT_LIFECYCLE_NAME}_row_id
    ON ${MV_PROJECT_LIFECYCLE_NAME} (row_id);
`;

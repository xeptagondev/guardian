# Guardian Indexer: PostgreSQL Migration & Dual-Source Architecture Design

**Date:** 2026-03-19
**Status:** Design Proposal (Research)
**Author:** Indexer Architect Agent

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Architecture Analysis](#2-current-architecture-analysis)
3. [A. PostgreSQL vs MongoDB Analysis](#3-a-postgresql-vs-mongodb-analysis)
4. [B. Dual-Source Architecture](#4-b-dual-source-architecture)
5. [C. Full PostgreSQL Schema Design](#5-c-full-postgresql-schema-design)
6. [D. Sync Pipeline Redesign](#6-d-sync-pipeline-redesign)
7. [E. Performance Advantages](#7-e-performance-advantages)
8. [Migration Strategy](#8-migration-strategy)

---

## 1. Executive Summary

The current Guardian Indexer stores all entity types in a single polymorphic MongoDB `message` collection, uses `$regex` for full-text search, performs N+1 count queries for detail views, and has no relational integrity between entities. This design document proposes:

1. **PostgreSQL as the primary datastore** with normalized tables, proper foreign keys, materialized views for aggregations, and `tsvector` for full-text search.
2. **Dual-source ingestion** combining the Hedera Mirror Node (blockchain-verified, network-wide data) with the Guardian Read API (internal state, workflow metadata, immediate availability).
3. **A redesigned sync pipeline** that eliminates the current bottleneck of sequential IPFS fetches and regex-based search.

---

## 2. Current Architecture Analysis

### 2.1 MongoDB Collections (from `indexer-common/src/entity/`)

| Collection | Entity File | Purpose | Record Count Profile |
|---|---|---|---|
| `message` | `message.ts` | **Central polymorphic table** — all entity types (30+ MessageTypes) in one collection | High (100K+) |
| `message_cache` | `message-cache.ts` | Raw ingestion buffer from Mirror Node | High (matches message) |
| `topic_cache` | `topic-cache.ts` | One row per topic — sync watermark | Low (100s) |
| `token_cache` | `token-cache.ts` | Token metadata + NFT enumeration progress | Medium (1000s) |
| `nft_cache` | `nft-cache.ts` | Individual NFT serial metadata | High (10K+) |
| `analytics` | `analytics.ts` | Daily aggregate snapshots | Low (365/year) |
| `project_coordinates` | `project-coordinates.ts` | Geo coordinates for projects | Low |
| `priority_queue` | `priority-queue.ts` | On-demand loading requests | Transient |
| `synchronization_task` | `synchronization-task.ts` | Distributed job locks | Very low (~16 rows) |
| `logs` | `logs.ts` | Error logs | Variable |
| GridFS | (built-in) | IPFS file binary storage | Medium |

### 2.2 The Polymorphic `message` Collection Problem

**File:** `indexer-common/src/entity/message.ts`

All 30+ entity types share one collection, differentiated by the `type` field (MessageType enum). Key structural problems:

1. **`options` field** — a schemaless `any` object that stores completely different data per entity type:
   - For STANDARD_REGISTRY: `{ did, registrantTopicId, attributes: { OrganizationName } }`
   - For INSTANCE_POLICY: `{ name, description, owner, instanceTopicId, originalMessageId }`
   - For VC_DOCUMENT: `{ issuer, relationships[], initId, startMessage }`
   - For SCHEMA: `{ name, owner, packageMessageId }`
   - For TOKEN: `{ tokenId, tokenName }`
   - For TOPIC: `{ childId, parentId, messageType }`
   - For TAG: `{ entity }`
   - For CONTRACT: `{ ... }`

2. **`analytics` field** — another embedded object populated by synchronizers with type-specific meanings:
   - For policies: `{ registryId, owner, tools[], tokens[], vcCount, vpCount, tokensCount, hash, hashMap, dynamicTopics[] }`
   - For VCs: `{ policyId, schemaId, schemaName, textSearch, tableFiles }`
   - For VPs: `{ policyId, schemaIds[], textSearch }`
   - For schemas: `{ textSearch, childSchemas[] }`

3. **`documents` field** — stores parsed IPFS content (varies from JSON-LD credentials to ZIP policy configs).

4. **`files` field** — array of IPFS CIDs whose meaning depends on entity type.

### 2.3 Current Query Patterns (from `entities.service.ts`)

**Critical observation:** Almost every "detail" endpoint performs **multiple sequential count queries** against the same `message` collection. This is the biggest performance issue.

#### Registry Detail (`GET_REGISTRY`) — 9 separate queries:
```
1. findOne(Message, { consensusTimestamp, type: STANDARD_REGISTRY })
2. findOne(MessageCache, { consensusTimestamp })
3. count(Message, { type: DID_DOCUMENT, topicId: registrantTopicId, 'options.did': { $ne: ... } })
4. count(Message, { type: VC_DOCUMENT, 'options.issuer': did })
5. count(Message, { type: VP_DOCUMENT, 'options.issuer': did })
6. count(Message, { type: INSTANCE_POLICY, action: PublishPolicy, 'options.owner': did })
7. count(Message, { type: TOOL, action: PublishTool, 'options.owner': did })
8. count(Message, { type: MODULE, action: PublishModule, 'options.owner': did })
9. count(Message, { type: ROLE_DOCUMENT, 'options.issuer': did })
+ count(TokenCache, { treasury: owner })
+ count(Message, { type: CONTRACT, action: CreateContract, owner })
```

#### Policy Detail (`GET_POLICY`) — 8 separate queries:
```
1. findOne(Message, { consensusTimestamp, type: INSTANCE_POLICY, action: PublishPolicy })
2. count(Message, { 'options.originalMessageId': messageId, type: INSTANCE_POLICY }) // derivations
3. findOne(MessageCache, { consensusTimestamp })
4. count(Message, { type: SCHEMA, action: $in[PublishSchema, PublishSystemSchema], topicId })
5. count(Message, { type: SCHEMA_PACKAGE, ... })
6. count(Message, { type: VC_DOCUMENT, 'analytics.policyId': timestamp })
7. count(Message, { type: VP_DOCUMENT, 'analytics.policyId': timestamp })
8. count(Message, { type: ROLE_DOCUMENT, 'analytics.policyId': timestamp })
+ count(Message, { type: FORMULA, topicId })
+ find(Message, { type: TAG, 'options.entity': Policy, topicId })
```

#### Topic Detail (`GET_TOPIC`) — 13 count queries (registries, topics, policies, tools, modules, schemas, tokens, roles, dids, vcs, vps, contracts, tags).

#### VC Detail (`GET_VC_DOCUMENT`) — the most complex:
- Loads document + documents
- Loads schema by cross-referencing schema CID
- Loads version history
- Loads formulas by `analytics.policyId`
- Loads policy by `analytics.policyId`
- Loads all relationships (recursive graph traversal)
- Loads schemas by topicId

#### Search (`GET_SEARCH_API`) — uses `$regex` on `analytics.textSearch`:
```javascript
{ 'analytics.textSearch': { $regex: `.*${escaped}.*`, $options: 'si' } }
```
This is a **full collection scan** — no index can be used for middle-of-string regex matches.

#### NFT Queries — require cross-collection join:
`getNFTs` fetches from `nft_cache`, then does a separate `find(Message, { consensusTimestamp: { $in: nftsConsensusTimestamps } })` to get analytics. This is a manual join.

### 2.4 Enrichment Synchronizers (from `synchronize-all.ts`)

16 cron-based synchronizers iterate the entire `message` collection:

| Synchronizer | Source File | What It Does |
|---|---|---|
| `SyncAnalytics` | `synchronize-analytics.ts` | Computes daily aggregate counts |
| `SyncProjects` | `synchronize-projects.ts` | Extracts geo coordinates from VCs |
| `SyncPolicies` | `synchronize-policy.ts` | Parses policy ZIPs, extracts tools/tokens, computes hash, finds SR |
| `SyncSchemas` | `synchronize-schema.ts` | Extracts schema metadata |
| `SyncSchemaPackage` | `synchronize-schema-package.ts` | Schema package processing |
| `SyncVCs` | `synchronize-vcs.ts` | Links VCs to policies/schemas, builds textSearch |
| `SyncVPs` | `synchronize-vp.ts` | Links VPs to policies/schemas |
| `SyncDid` | `synchronize-dids.ts` | DID enrichment |
| `SyncRegistries` | `synchronize-registry.ts` | Registry enrichment |
| `SyncRoles` | `synchronize-role.ts` | Role enrichment |
| `SyncModules` | `synchronize-module.ts` | Module enrichment |
| `SyncTools` | `synchronize-tool.ts` | Tool enrichment |
| `SyncTopics` | `synchronize-topic.ts` | Topic enrichment |
| `SyncContracts` | `synchronize-contracts.ts` | Contract enrichment |
| `SyncLabels` | `synchronize-labels.ts` | Label enrichment |
| `SyncFormulas` | `synchronize-formula.ts` | Formula enrichment |

Each synchronizer loads the **entire dataset** of its entity type plus related entities into memory, then iterates and updates `analytics` fields. The policy synchronizer, for example, loads ALL policies, ALL SRs, ALL topics, ALL documents (VC/VP counts), and ALL tokens.

---

## 3. A. PostgreSQL vs MongoDB Analysis

### 3.1 Why PostgreSQL Wins for This Workload

| Dimension | MongoDB (Current) | PostgreSQL (Proposed) |
|---|---|---|
| **Multi-entity counts** | N sequential `count()` queries per detail view | Single `SELECT` with `COUNT(*) FILTER (WHERE ...)` or subqueries |
| **Cross-collection joins** | Manual application-level joins (NFTs→Messages, Tokens→Messages) | Native `JOIN` with FK integrity |
| **Full-text search** | `$regex` on concatenated string — O(n) scan | `tsvector` with GIN index — O(log n) |
| **Aggregations** | Computed by cron synchronizers, stale up to 1 hour | Materialized views, refreshable on demand |
| **Analytics object** | Embedded, varies by type, no schema enforcement | Normalized into proper columns with constraints |
| **Relationship graph** | Recursive application-level traversal | Recursive CTE (`WITH RECURSIVE`) |
| **Polymorphic storage** | All types in one collection, `any` typed fields | Inheritance (shared base + type-specific tables) or JSONB |
| **Concurrent writes** | Document-level locking, no transactions | MVCC, full ACID transactions |
| **Schema evolution** | Schemaless but no validation | Migrations with `ALTER TABLE`, constraints enforce correctness |

### 3.2 Collection-to-Table Mapping

#### The Polymorphic `message` Collection: Split Strategy

The `message` collection should be **split into a base table + type-specific tables** using PostgreSQL table inheritance or a joined-table approach. The `options` field contains completely different data per type, making a single table with nullable columns impractical.

**Recommended approach: Shared `message_base` table + type-specific tables with foreign keys.**

**Rationale:**
- Queries almost always filter by `type` first (every list endpoint adds `filters.type = MessageType.X`)
- The `options` field has completely different shapes per type
- Counts, joins, and aggregations become much simpler when each type has its own table
- The `analytics` embedded object should become columns on the type-specific table or a separate analytics table

**What stays in one table:**
- `message_cache` (raw ingestion buffer) — keeps all types since it's processed sequentially
- The base `message` fields that are universal across types

---

## 4. B. Dual-Source Architecture

### 4.1 Data Available ONLY Through Guardian API

**File references:** `api-gateway/src/api/service/` — all service files

The Guardian API (port 3000) provides authenticated endpoints that expose internal state not published to Hedera:

| Data | Guardian API Endpoint | Why Not on Chain |
|---|---|---|
| **Policy status** (DRAFT, DRY_RUN, PUBLISH_ERROR, DISCONTINUED) | `GET /policies` | Only PUBLISHED policies get Hedera messages |
| **Policy config** (full block tree, navigation, groups) | `GET /policies/:id` | Stored in Guardian MongoDB, referenced by IPFS CID |
| **User profiles** (username, role, Hedera credentials status) | `GET /profiles/:username` | Internal auth system |
| **User sessions & permissions** | `GET /accounts/session` | Internal auth |
| **Approval status** (approve/reject on VCs) | `GET /policies/:id/blocks/:blockId/data` | Internal workflow state |
| **Document assignment** (assignedTo, assignedToGroup) | VcDocument entity (`common/src/entity/vc-document.ts`) | Internal field |
| **Policy workflow progress** (which block a user is at) | Block state API | Runtime state |
| **Token-policy associations** (which policies use which tokens) | `GET /tokens` (with policyIds) | Cross-reference in Guardian DB |
| **Schema draft/review state** | `GET /schemas` (status: DRAFT, PUBLISHED) | Only PUBLISHED on chain |
| **Policy categories & branding** | `GET /policies/categories`, branding API | Internal metadata |
| **Dry-run data** | `GET /policies/:id/dry-run` | Ephemeral test data |
| **Task progress** (async operation status) | `GET /tasks/:taskId` | Internal task queue |
| **Suggestions & AI** | `GET /suggestions`, `/ai-suggestions` | Internal AI features |
| **Notifications** | `GET /notifications` | Internal messaging |
| **Comments on policies** | `GET /policy-comments` | Internal discussion |
| **Formula definitions** | `GET /formulas` | Published to chain but more detail locally |
| **Policy labels** | `GET /policy-labels` | Similar to formulas |

### 4.2 Data Available ONLY Through Mirror Node

| Data | Mirror Node Endpoint | Why Not in Guardian API |
|---|---|---|
| **Consensus timestamps** (authoritative) | `/topics/{id}/messages` | Guardian knows its own, but not other organizations' |
| **Topic sequence numbers** | `/topics/{id}/messages` | Blockchain ordering |
| **Raw HCS messages** (from any Guardian instance) | `/topics/{id}/messages` | Network-wide visibility |
| **Token supply** (authoritative, real-time) | `/tokens/{id}` | Guardian knows only what it minted |
| **NFT serial data** (authoritative) | `/tokens/{id}/nfts` | Complete on-chain record |
| **NFT transaction history** | `/tokens/{id}/nfts/{serial}/transactions` | On-chain provenance |
| **Third-party organization data** | Various topic messages | Not in any single Guardian instance |
| **Cross-organization token transfers** | `/tokens/{id}/nfts/{serial}/transactions` | On-chain only |
| **Account balances** | `/accounts/{id}/tokens` | On-chain state |

### 4.3 Data Available from BOTH Sources

| Data | Guardian API | Mirror Node | Authoritative Source |
|---|---|---|---|
| Published policies | Full detail + internal state | HCS message + IPFS CID | **Mirror Node** for existence proof, **Guardian API** for rich detail |
| Published schemas | Full JSON-LD + internal metadata | HCS message + IPFS CID | Mirror Node for proof, Guardian for content |
| VCs/VPs | Full document + approval status | HCS message + IPFS CID | Mirror Node for chain proof, Guardian for workflow state |
| DIDs | DID document | HCS message | Mirror Node for resolution, Guardian for profile context |
| Token metadata | Name, symbol, type, policies | Name, symbol, type, supply | **Mirror Node** for supply, **Guardian API** for policy associations |
| Registry (SR) info | Full profile, org name, capabilities | HCS registration message | Guardian for rich profile, Mirror Node for on-chain proof |

### 4.4 Dual-Source Sync Pipeline Design

```
                    ┌─────────────────────────┐
                    │   Guardian Read API      │
                    │   (Self-Organization)    │
                    │                          │
                    │ Polls: /policies,        │
                    │ /schemas, /tokens,       │
                    │ /profiles, /vc-documents │
                    └────────┬────────────────┘
                             │ Fast, Rich, Immediate
                             │ (no blockchain delay)
                             ▼
┌──────────────┐    ┌──────────────────────────────┐    ┌──────────────────────┐
│ Hedera       │    │  DATA RECONCILIATION LAYER   │    │   PostgreSQL         │
│ Mirror Node  │───▶│                              │───▶│                      │
│              │    │  - Dedup by consensusTimestamp│    │  Normalized tables   │
│ Polls:       │    │  - Mirror Node = authoritative│   │  Materialized views  │
│ /topics/     │    │    for on-chain proof         │    │  tsvector search     │
│ /tokens/     │    │  - Guardian API = authoritative│   │  JSONB for flexible  │
│ /tokens/nfts │    │    for internal state         │    │                      │
└──────────────┘    │  - Conflict resolution:       │    └──────────────────────┘
                    │    latest_modified wins        │
                    │  - Source tracking column      │
                    └──────────────────────────────┘
```

**Key principles:**

1. **Guardian API for self-organization data (primary source):**
   - Polled every 30-60 seconds
   - Provides immediate availability (no waiting for Hedera consensus + IPFS fetch)
   - Rich data: policy config, workflow state, approval status, user profiles
   - Contains internal-only state (DRAFT policies, assignment, groups)
   - Authenticated access (needs API key or service token)

2. **Mirror Node for network-wide/third-party data:**
   - Same polling as today (topic sync, token sync)
   - Provides blockchain-verified existence proofs
   - Only source for other organizations' data
   - Authoritative for consensus timestamps, sequence numbers, token supply

3. **Reconciliation rules:**
   - Each record tracks `data_source` (enum: 'mirror_node', 'guardian_api', 'both')
   - `consensus_timestamp` from Mirror Node is the canonical identifier
   - For self-org data: Guardian API data merges into the record, enriching it with internal state
   - For third-party data: Mirror Node is the only source
   - If both sources provide the same field, Mirror Node wins for on-chain data, Guardian API wins for internal state

4. **Authentication for Guardian API:**
   - The indexer runs as an internal service with a dedicated service account
   - Uses long-lived API token (configurable via `GUARDIAN_API_TOKEN` env var)
   - Read-only access (only GET endpoints)
   - Optional: can be disabled for pure Mirror Node indexing (current behavior)

---

## 5. C. Full PostgreSQL Schema Design

### 5.1 Core Tables

```sql
-- ============================================================
-- ENUMS
-- ============================================================

CREATE TYPE message_type AS ENUM (
    'EVC-Document', 'VC-Document', 'DID-Document', 'Schema',
    'schema-document', 'Policy', 'Instance-Policy', 'VP-Document',
    'Standard Registry', 'Topic', 'Token', 'Module', 'Tool', 'Tag',
    'Role-Document', 'Synchronization Event', 'Contract',
    'Guardian-Role-Document', 'User-Permissions',
    'Policy-Statistic', 'Policy-Label', 'Formula',
    'Schema-Package', 'Policy-Diff', 'Policy-Action',
    'Policy-Discussion', 'Policy-Comment'
);

CREATE TYPE message_action AS ENUM (
    'create-did-document', 'create-vc-document', 'create-policy',
    'publish-policy', 'delete-policy', 'create-schema',
    'publish-schema', 'publish-schemas', 'delete-schema',
    'create-topic', 'create-vp-document', 'publish-system-schema',
    'publish-system-schemas', 'Init', 'change-message-status',
    'revoke-document', 'delete-document', 'token-issue',
    'create-token', 'create-multi-policy', 'mint',
    'publish-module', 'publish-tag', 'delete-tag',
    'publish-tool', 'create-tool', 'create-contract',
    'discontinue-policy', 'deferred-discontinue-policy',
    'migrate-vc-document', 'migrate-vp-document',
    'create-role', 'update-role', 'delete-role', 'set-role',
    'publish-policy-statistic', 'create-assessment-document',
    'publish-policy-label', 'create-label-document',
    'publish-formula', 'create-policy-comment',
    'create-policy-discussion'
);

CREATE TYPE data_source AS ENUM ('mirror_node', 'guardian_api', 'both');
CREATE TYPE processing_status AS ENUM ('LOADING', 'LOADED', 'ERROR');
CREATE TYPE priority_status AS ENUM ('WAITING', 'PROCESSING', 'DONE', 'ERROR');
CREATE TYPE token_type AS ENUM ('FUNGIBLE_COMMON', 'NON_FUNGIBLE_UNIQUE');

-- ============================================================
-- BASE MESSAGE TABLE (shared columns across all entity types)
-- ============================================================

CREATE TABLE message (
    id                   BIGSERIAL PRIMARY KEY,
    consensus_timestamp  VARCHAR(30) NOT NULL UNIQUE,
    topic_id             VARCHAR(20) NOT NULL,
    owner                VARCHAR(200),
    uuid                 VARCHAR(100),
    type                 message_type NOT NULL,
    action               message_action,
    status               VARCHAR(50),
    status_reason        TEXT,
    status_message       TEXT,
    status_owner         VARCHAR(200),
    lang                 VARCHAR(10),
    response_type        VARCHAR(50),
    virtual              BOOLEAN DEFAULT FALSE,
    loaded               BOOLEAN DEFAULT FALSE,
    sequence_number      INTEGER,
    files                TEXT[],            -- IPFS CIDs
    documents            JSONB,             -- Parsed document content
    options              JSONB,             -- Type-specific structured data
    topics               TEXT[],
    tokens               TEXT[],
    data_source          data_source DEFAULT 'mirror_node',
    last_update          BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
    analytics_update     BIGINT,
    coord_update         BIGINT,

    -- Full-text search vector (replaces analytics.textSearch)
    search_vector        tsvector,

    created_at           TIMESTAMPTZ DEFAULT NOW(),
    updated_at           TIMESTAMPTZ DEFAULT NOW()
);

-- Core indexes (mirrors existing MongoDB indexes)
CREATE INDEX idx_message_topic_id ON message(topic_id);
CREATE INDEX idx_message_type ON message(type);
CREATE INDEX idx_message_status ON message(status);
CREATE INDEX idx_message_last_update ON message(last_update);
CREATE INDEX idx_message_loaded ON message(loaded);
CREATE INDEX idx_message_owner ON message(owner);
CREATE INDEX idx_message_uuid ON message(uuid);
CREATE INDEX idx_message_type_action ON message(type, action);
CREATE INDEX idx_message_type_topic ON message(type, topic_id);

-- Full-text search index (replaces $regex on analytics.textSearch)
CREATE INDEX idx_message_search ON message USING GIN(search_vector);

-- Partial indexes for common filtered queries
CREATE INDEX idx_message_published_policies ON message(consensus_timestamp)
    WHERE type = 'Instance-Policy' AND action = 'publish-policy';
CREATE INDEX idx_message_published_schemas ON message(consensus_timestamp)
    WHERE type = 'Schema' AND action IN ('publish-schema', 'publish-system-schema');
CREATE INDEX idx_message_vc_documents ON message(consensus_timestamp)
    WHERE type = 'VC-Document';
CREATE INDEX idx_message_vp_documents ON message(consensus_timestamp)
    WHERE type = 'VP-Document';
CREATE INDEX idx_message_standard_registries ON message(consensus_timestamp)
    WHERE type = 'Standard Registry';

-- JSONB indexes for the options field (replaces 'options.did', 'options.issuer', etc.)
CREATE INDEX idx_message_options_did ON message USING GIN((options -> 'did'));
CREATE INDEX idx_message_options_issuer ON message USING GIN((options -> 'issuer'));
CREATE INDEX idx_message_options_owner ON message USING GIN((options -> 'owner'));
CREATE INDEX idx_message_options_relationships ON message USING GIN((options -> 'relationships'));

-- ============================================================
-- ENTITY-SPECIFIC ANALYTICS TABLES
-- ============================================================

-- Policy analytics (replaces embedded analytics for Instance-Policy type)
CREATE TABLE policy_analytics (
    id                   BIGSERIAL PRIMARY KEY,
    message_id           BIGINT NOT NULL REFERENCES message(id) ON DELETE CASCADE,
    consensus_timestamp  VARCHAR(30) NOT NULL UNIQUE,
    registry_id          VARCHAR(30) REFERENCES message(consensus_timestamp),
    registry_did         VARCHAR(200),
    tools                TEXT[],
    tokens               TEXT[],
    vc_count             INTEGER DEFAULT 0,
    vp_count             INTEGER DEFAULT 0,
    tokens_count         BIGINT DEFAULT 0,
    derivations_count    INTEGER DEFAULT 0,
    hash                 TEXT,
    hash_map             JSONB,
    dynamic_topics       TEXT[],
    tags                 TEXT[],
    updated_at           TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_policy_analytics_message ON policy_analytics(message_id);
CREATE INDEX idx_policy_analytics_registry ON policy_analytics(registry_id);
CREATE INDEX idx_policy_analytics_tools ON policy_analytics USING GIN(tools);

-- VC/VP Document analytics (replaces embedded analytics for VC/VP types)
CREATE TABLE document_analytics (
    id                   BIGSERIAL PRIMARY KEY,
    message_id           BIGINT NOT NULL REFERENCES message(id) ON DELETE CASCADE,
    consensus_timestamp  VARCHAR(30) NOT NULL UNIQUE,
    policy_id            VARCHAR(30),  -- References policy consensus_timestamp
    schema_id            VARCHAR(30),  -- References schema consensus_timestamp
    schema_name          VARCHAR(500),
    issuer               VARCHAR(200),
    schema_ids           TEXT[],       -- For VPs that reference multiple schemas
    token_id             VARCHAR(20),
    labels               TEXT[],
    label_name           VARCHAR(500),
    table_files          JSONB,
    updated_at           TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_doc_analytics_message ON document_analytics(message_id);
CREATE INDEX idx_doc_analytics_policy ON document_analytics(policy_id);
CREATE INDEX idx_doc_analytics_schema ON document_analytics(schema_id);
CREATE INDEX idx_doc_analytics_issuer ON document_analytics(issuer);

-- Schema analytics
CREATE TABLE schema_analytics (
    id                   BIGSERIAL PRIMARY KEY,
    message_id           BIGINT NOT NULL REFERENCES message(id) ON DELETE CASCADE,
    consensus_timestamp  VARCHAR(30) NOT NULL UNIQUE,
    child_schemas        JSONB,  -- Array of child schema references
    properties           TEXT[],
    unpacked             BOOLEAN DEFAULT FALSE,
    updated_at           TIMESTAMPTZ DEFAULT NOW()
);

-- Registry analytics
CREATE TABLE registry_analytics (
    id                   BIGSERIAL PRIMARY KEY,
    message_id           BIGINT NOT NULL REFERENCES message(id) ON DELETE CASCADE,
    consensus_timestamp  VARCHAR(30) NOT NULL UNIQUE,
    did                  VARCHAR(200),
    registrant_topic_id  VARCHAR(20),
    organization_name    VARCHAR(500),
    updated_at           TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_registry_analytics_did ON registry_analytics(did);

-- ============================================================
-- CACHE TABLES (worker writes)
-- ============================================================

CREATE TABLE message_cache (
    id                     BIGSERIAL PRIMARY KEY,
    consensus_timestamp    VARCHAR(30) NOT NULL UNIQUE,
    topic_id               VARCHAR(20) NOT NULL,
    status                 processing_status NOT NULL DEFAULT 'LOADING',
    last_update            BIGINT NOT NULL,
    message                TEXT NOT NULL,
    sequence_number        INTEGER NOT NULL,
    owner                  VARCHAR(200),
    chunk_id               VARCHAR(100),
    chunk_number           INTEGER,
    chunk_total            INTEGER,
    type                   VARCHAR(50),
    data                   TEXT,
    priority_date          TIMESTAMPTZ,
    priority_status        priority_status,
    priority_status_date   TIMESTAMPTZ,
    priority_timestamp     BIGINT
);

CREATE INDEX idx_mcache_status ON message_cache(status);
CREATE INDEX idx_mcache_chunk_id ON message_cache(chunk_id);
CREATE INDEX idx_mcache_type ON message_cache(type);
CREATE INDEX idx_mcache_priority ON message_cache(priority_date);
CREATE INDEX idx_mcache_priority_topic ON message_cache(priority_date, topic_id);

CREATE TABLE topic_cache (
    id                     BIGSERIAL PRIMARY KEY,
    topic_id               VARCHAR(20) NOT NULL UNIQUE,
    status                 VARCHAR(20) NOT NULL,
    last_update            BIGINT NOT NULL,
    messages               INTEGER NOT NULL DEFAULT 0,
    has_next               BOOLEAN DEFAULT FALSE,
    priority_date          TIMESTAMPTZ,
    priority_status        priority_status,
    priority_status_date   TIMESTAMPTZ,
    priority_timestamp     BIGINT
);

CREATE INDEX idx_tcache_status ON topic_cache(status);
CREATE INDEX idx_tcache_has_next ON topic_cache(has_next);

CREATE TABLE token_cache (
    id                     BIGSERIAL PRIMARY KEY,
    token_id               VARCHAR(20) NOT NULL UNIQUE,
    status                 VARCHAR(20) NOT NULL,
    created_timestamp      VARCHAR(30),
    modified_timestamp     VARCHAR(30),
    last_update            BIGINT NOT NULL,
    serial_number          INTEGER DEFAULT 0,
    has_next               BOOLEAN DEFAULT FALSE,
    name                   VARCHAR(200),
    symbol                 VARCHAR(20),
    type                   token_type,
    treasury               VARCHAR(20),
    memo                   TEXT,
    total_supply           NUMERIC,
    decimals               INTEGER,
    priority_date          TIMESTAMPTZ,
    priority_status        priority_status,
    priority_status_date   TIMESTAMPTZ,
    priority_timestamp     BIGINT
);

CREATE INDEX idx_tokencache_status ON token_cache(status);
CREATE INDEX idx_tokencache_treasury ON token_cache(treasury);
CREATE INDEX idx_tokencache_type ON token_cache(type);

CREATE TABLE nft_cache (
    id                     BIGSERIAL PRIMARY KEY,
    token_id               VARCHAR(20) NOT NULL,
    serial_number          INTEGER NOT NULL,
    last_update            BIGINT NOT NULL,
    metadata               VARCHAR(100),  -- consensus_timestamp reference
    UNIQUE(token_id, serial_number)
);

CREATE INDEX idx_nft_token ON nft_cache(token_id);
CREATE INDEX idx_nft_metadata ON nft_cache(metadata);

-- ============================================================
-- OPERATIONAL TABLES
-- ============================================================

CREATE TABLE analytics_snapshot (
    id                     BIGSERIAL PRIMARY KEY,
    date                   DATE NOT NULL UNIQUE,
    registries             INTEGER DEFAULT 0,
    methodologies          INTEGER DEFAULT 0,
    projects               INTEGER DEFAULT 0,
    total_issuance         NUMERIC DEFAULT 0,
    total_serialized       NUMERIC DEFAULT 0,
    total_fungible         NUMERIC DEFAULT 0
);

CREATE TABLE project_coordinates (
    id                     BIGSERIAL PRIMARY KEY,
    coordinates            VARCHAR(100) NOT NULL UNIQUE,
    project_id             VARCHAR(100) NOT NULL
);

CREATE INDEX idx_projcoord_project ON project_coordinates(project_id);

CREATE TABLE priority_queue (
    id                     BIGSERIAL PRIMARY KEY,
    priority_timestamp     BIGINT NOT NULL,
    entity_id              VARCHAR(20),
    type                   VARCHAR(10) CHECK (type IN ('Topic', 'Token')),
    priority_status        priority_status,
    priority_status_date   TIMESTAMPTZ,
    created_at             TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE synchronization_task (
    id                     BIGSERIAL PRIMARY KEY,
    task_name              VARCHAR(100) NOT NULL UNIQUE,
    date                   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE logs (
    id                     BIGSERIAL PRIMARY KEY,
    error                  TEXT,
    tag                    VARCHAR(100),
    created_at             TIMESTAMPTZ DEFAULT NOW()
);

-- File storage (replaces GridFS)
CREATE TABLE ipfs_files (
    id                     BIGSERIAL PRIMARY KEY,
    cid                    VARCHAR(100) NOT NULL UNIQUE,
    content                BYTEA NOT NULL,
    size                   INTEGER,
    created_at             TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- GUARDIAN API DATA (new — data from dual-source)
-- ============================================================

-- Policy internal state (from Guardian API, not on-chain)
CREATE TABLE guardian_policy_state (
    id                     BIGSERIAL PRIMARY KEY,
    policy_message_id      VARCHAR(30) REFERENCES message(consensus_timestamp),
    guardian_internal_id    VARCHAR(50),  -- Guardian's MongoDB ObjectId
    status                 VARCHAR(50),  -- DRAFT, DRY_RUN, PUBLISH_ERROR, PUBLISHED, DISCONTINUED
    policy_tag             VARCHAR(200),
    code_version           VARCHAR(20),
    policy_roles           JSONB,
    policy_groups          JSONB,
    policy_navigation      JSONB,
    policy_tokens          JSONB,
    instance_topic_id      VARCHAR(20),
    synchronization_topic_id VARCHAR(20),
    comments_topic_id      VARCHAR(20),
    categories             JSONB,
    last_synced_at         TIMESTAMPTZ DEFAULT NOW()
);

-- User profiles (from Guardian API)
CREATE TABLE guardian_user_profile (
    id                     BIGSERIAL PRIMARY KEY,
    username               VARCHAR(200) NOT NULL UNIQUE,
    did                    VARCHAR(200),
    hedera_account_id      VARCHAR(20),
    role                   VARCHAR(50),
    parent_did             VARCHAR(200),  -- For users under an SR
    profile_topic_id       VARCHAR(20),
    last_synced_at         TIMESTAMPTZ DEFAULT NOW()
);

-- VC workflow state (from Guardian API)
CREATE TABLE guardian_document_state (
    id                     BIGSERIAL PRIMARY KEY,
    document_message_id    VARCHAR(30) REFERENCES message(consensus_timestamp),
    approval_status        VARCHAR(50),  -- APPROVED, REJECTED, PENDING
    assigned_to            VARCHAR(200),
    assigned_to_group      VARCHAR(200),
    policy_id_internal     VARCHAR(50),
    tag                    VARCHAR(200),
    comment                TEXT,
    last_synced_at         TIMESTAMPTZ DEFAULT NOW()
);
```

### 5.2 Materialized Views for Business Aggregations

These replace the N+1 count queries and the cron-based SyncAnalytics.

```sql
-- ============================================================
-- MATERIALIZED VIEW: Registry activity summary
-- Replaces the 9 count queries in getRegistry()
-- ============================================================

CREATE MATERIALIZED VIEW mv_registry_activity AS
SELECT
    r.consensus_timestamp AS registry_id,
    r.options->>'did' AS registry_did,
    r.options->>'registrantTopicId' AS registrant_topic_id,
    r.owner,

    (SELECT COUNT(*) FROM message d
     WHERE d.type = 'DID-Document'
       AND d.topic_id = r.options->>'registrantTopicId'
       AND d.options->>'did' != r.options->>'did')
    AS user_count,

    (SELECT COUNT(*) FROM message v
     WHERE v.type = 'VC-Document'
       AND v.options->>'issuer' = r.options->>'did')
    AS vc_count,

    (SELECT COUNT(*) FROM message v
     WHERE v.type = 'VP-Document'
       AND v.options->>'issuer' = r.options->>'did')
    AS vp_count,

    (SELECT COUNT(*) FROM message p
     WHERE p.type = 'Instance-Policy'
       AND p.action = 'publish-policy'
       AND p.options->>'owner' = r.options->>'did')
    AS policy_count,

    (SELECT COUNT(*) FROM message t
     WHERE t.type = 'Tool'
       AND t.action = 'publish-tool'
       AND t.options->>'owner' = r.options->>'did')
    AS tool_count,

    (SELECT COUNT(*) FROM message m
     WHERE m.type = 'Module'
       AND m.action = 'publish-module'
       AND m.options->>'owner' = r.options->>'did')
    AS module_count,

    (SELECT COUNT(*) FROM message ro
     WHERE ro.type = 'Role-Document'
       AND ro.options->>'issuer' = r.options->>'did')
    AS role_count,

    (SELECT COUNT(*) FROM token_cache tc
     WHERE tc.treasury = r.owner)
    AS token_count,

    (SELECT COUNT(*) FROM message c
     WHERE c.type = 'Contract'
       AND c.action = 'create-contract'
       AND c.owner = r.owner)
    AS contract_count

FROM message r
WHERE r.type = 'Standard Registry';

CREATE UNIQUE INDEX idx_mv_registry_activity ON mv_registry_activity(registry_id);

-- ============================================================
-- MATERIALIZED VIEW: Policy activity summary
-- Replaces the 8 count queries in getPolicy()
-- ============================================================

CREATE MATERIALIZED VIEW mv_policy_activity AS
SELECT
    p.consensus_timestamp AS policy_id,
    p.topic_id,
    p.options->>'instanceTopicId' AS instance_topic_id,

    (SELECT COUNT(*) FROM message s
     WHERE s.type = 'Schema'
       AND s.action IN ('publish-schema', 'publish-system-schema')
       AND s.topic_id = p.topic_id)
    AS schema_count,

    (SELECT COUNT(*) FROM message sp
     WHERE sp.type = 'Schema-Package'
       AND sp.action IN ('publish-schemas', 'publish-system-schemas')
       AND sp.topic_id = p.topic_id)
    AS schema_package_count,

    (SELECT COUNT(*) FROM message v
     JOIN document_analytics da ON da.consensus_timestamp = v.consensus_timestamp
     WHERE v.type = 'VC-Document'
       AND da.policy_id = p.consensus_timestamp)
    AS vc_count,

    (SELECT COUNT(*) FROM message v
     JOIN document_analytics da ON da.consensus_timestamp = v.consensus_timestamp
     WHERE v.type = 'VP-Document'
       AND da.policy_id = p.consensus_timestamp)
    AS vp_count,

    (SELECT COUNT(*) FROM message ro
     JOIN document_analytics da ON da.consensus_timestamp = ro.consensus_timestamp
     WHERE ro.type = 'Role-Document'
       AND da.policy_id = p.consensus_timestamp)
    AS role_count,

    (SELECT COUNT(*) FROM message f
     WHERE f.type = 'Formula'
       AND f.topic_id = p.topic_id)
    AS formula_count,

    (SELECT COUNT(*) FROM message d
     WHERE d.options->>'originalMessageId' = p.consensus_timestamp
       AND d.type = 'Instance-Policy'
       AND d.action = 'publish-policy')
    AS derivation_count

FROM message p
WHERE p.type = 'Instance-Policy'
  AND p.action = 'publish-policy';

CREATE UNIQUE INDEX idx_mv_policy_activity ON mv_policy_activity(policy_id);

-- ============================================================
-- MATERIALIZED VIEW: Topic activity summary
-- Replaces the 13 count queries in getTopic()
-- ============================================================

CREATE MATERIALIZED VIEW mv_topic_activity AS
SELECT
    t.topic_id,
    COUNT(*) FILTER (WHERE m.type = 'Standard Registry') AS registry_count,
    COUNT(*) FILTER (WHERE m.type = 'Topic' AND m.action = 'create-topic'
                      AND m.options->>'parentId' = t.topic_id) AS child_topic_count,
    COUNT(*) FILTER (WHERE m.type = 'Instance-Policy' AND m.action = 'publish-policy') AS policy_count,
    COUNT(*) FILTER (WHERE m.type = 'Tool' AND m.action = 'publish-tool') AS tool_count,
    COUNT(*) FILTER (WHERE m.type = 'Module' AND m.action = 'publish-module') AS module_count,
    COUNT(*) FILTER (WHERE m.type = 'Schema'
                      AND m.action IN ('publish-schema', 'publish-system-schema')) AS schema_count,
    COUNT(*) FILTER (WHERE m.type = 'Token') AS token_count,
    COUNT(*) FILTER (WHERE m.type = 'Role-Document') AS role_count,
    COUNT(*) FILTER (WHERE m.type = 'DID-Document') AS did_count,
    COUNT(*) FILTER (WHERE m.type = 'VC-Document') AS vc_count,
    COUNT(*) FILTER (WHERE m.type = 'VP-Document') AS vp_count,
    COUNT(*) FILTER (WHERE m.type = 'Contract') AS contract_count
FROM topic_cache t
LEFT JOIN message m ON m.topic_id = t.topic_id
GROUP BY t.topic_id;

CREATE UNIQUE INDEX idx_mv_topic_activity ON mv_topic_activity(topic_id);

-- ============================================================
-- MATERIALIZED VIEW: Landing analytics (latest daily stats)
-- Replaces the analytics collection
-- ============================================================

CREATE MATERIALIZED VIEW mv_landing_analytics AS
SELECT
    date_trunc('day', to_timestamp(m.last_update / 1000.0)) AS date,
    COUNT(*) FILTER (WHERE m.type = 'Standard Registry') AS registries,
    COUNT(*) FILTER (WHERE m.type = 'Instance-Policy' AND m.action = 'publish-policy') AS methodologies,
    COUNT(DISTINCT pc.project_id) AS projects,
    COALESCE(SUM(tc.total_supply) FILTER (WHERE tc.type = 'NON_FUNGIBLE_UNIQUE'), 0) AS total_serialized,
    COALESCE(SUM(tc.total_supply) FILTER (WHERE tc.type = 'FUNGIBLE_COMMON'), 0) AS total_fungible,
    COALESCE(SUM(tc.total_supply), 0) AS total_issuance
FROM message m
LEFT JOIN project_coordinates pc ON TRUE
LEFT JOIN token_cache tc ON TRUE
WHERE m.type IN ('Standard Registry', 'Instance-Policy')
GROUP BY date_trunc('day', to_timestamp(m.last_update / 1000.0))
ORDER BY date DESC
LIMIT 10;

-- Refresh strategy: call periodically
-- REFRESH MATERIALIZED VIEW CONCURRENTLY mv_registry_activity;
-- REFRESH MATERIALIZED VIEW CONCURRENTLY mv_policy_activity;
-- REFRESH MATERIALIZED VIEW CONCURRENTLY mv_topic_activity;
```

### 5.3 Full-Text Search with tsvector

Replaces the `$regex` on `analytics.textSearch` concatenated string.

```sql
-- Function to build search vector from message data
CREATE OR REPLACE FUNCTION build_search_vector(msg message) RETURNS tsvector AS $$
DECLARE
    vec tsvector;
BEGIN
    vec := to_tsvector('simple',
        COALESCE(msg.topic_id, '') || ' ' ||
        COALESCE(msg.owner, '') || ' ' ||
        COALESCE(msg.consensus_timestamp, '') || ' ' ||
        COALESCE(msg.uuid, '') || ' ' ||
        COALESCE(msg.status, '') || ' ' ||
        COALESCE(msg.type::text, '') || ' ' ||
        COALESCE(msg.lang, '') || ' ' ||
        COALESCE(msg.options->>'name', '') || ' ' ||
        COALESCE(msg.options->>'did', '') || ' ' ||
        COALESCE(msg.options->>'issuer', '') || ' ' ||
        COALESCE(msg.options->>'owner', '') || ' ' ||
        COALESCE(msg.options->>'role', '') || ' ' ||
        COALESCE(msg.options->>'tokenName', '') || ' ' ||
        COALESCE(msg.options->>'tokenId', '') || ' ' ||
        COALESCE(msg.options->>'description', '')
    );
    RETURN vec;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Trigger to auto-update search vector
CREATE OR REPLACE FUNCTION update_search_vector() RETURNS trigger AS $$
BEGIN
    NEW.search_vector := build_search_vector(NEW);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trig_message_search_vector
    BEFORE INSERT OR UPDATE ON message
    FOR EACH ROW EXECUTE FUNCTION update_search_vector();

-- Search query (replaces the $regex approach)
-- Current: { 'analytics.textSearch': { $regex: '.*term.*', $options: 'si' } }
-- New:
SELECT * FROM message
WHERE search_vector @@ plainto_tsquery('simple', 'search term')
ORDER BY ts_rank(search_vector, plainto_tsquery('simple', 'search term')) DESC
LIMIT 10 OFFSET 0;

-- For partial/prefix matching (like the current regex behavior):
SELECT * FROM message
WHERE search_vector @@ to_tsquery('simple', 'prefix:*')
ORDER BY ts_rank(search_vector, to_tsquery('simple', 'prefix:*')) DESC;

-- Combined search (mirrors current SearchService behavior):
SELECT * FROM (
    SELECT 'token' AS source, token_id AS id, name, symbol, NULL AS type
    FROM token_cache WHERE token_id = :search
    UNION ALL
    SELECT 'message' AS source, consensus_timestamp, NULL, NULL, type::text
    FROM message
    WHERE search_vector @@ plainto_tsquery('simple', :search)
       OR topic_id = :search
       OR consensus_timestamp = :search
       OR owner = :search
) results
LIMIT :limit OFFSET :offset;
```

### 5.4 Relationship Graph with Recursive CTE

Replaces the recursive `addRelationships()` function in `entities.service.ts`.

```sql
-- Current: recursive async function that does N+1 findOne queries
-- New: single recursive CTE query

WITH RECURSIVE relationship_graph AS (
    -- Base case: the target message
    SELECT
        m.id, m.consensus_timestamp, m.type, m.options,
        0 AS depth
    FROM message m
    WHERE m.consensus_timestamp = :target_id

    UNION

    -- Recursive case: follow options.relationships
    SELECT
        m2.id, m2.consensus_timestamp, m2.type, m2.options,
        rg.depth + 1
    FROM relationship_graph rg
    CROSS JOIN LATERAL jsonb_array_elements_text(rg.options->'relationships') AS rel_id
    JOIN message m2 ON m2.consensus_timestamp = rel_id
    WHERE m2.type = 'VC-Document'
      AND rg.depth < 10  -- prevent infinite recursion
)
SELECT DISTINCT ON (consensus_timestamp) *
FROM relationship_graph;
```

---

## 6. D. Sync Pipeline Redesign

### 6.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    INDEXER-WORKER-SERVICE                        │
│                                                                 │
│  ┌─────────────────┐  ┌──────────────────┐                     │
│  │ Mirror Node     │  │ Guardian API     │                     │
│  │ Poller          │  │ Poller           │                     │
│  │                 │  │                  │                     │
│  │ Topics: 5 conc  │  │ Policies: 60s    │                     │
│  │ Messages: 10    │  │ Schemas: 120s    │                     │
│  │ Tokens: 2       │  │ Profiles: 300s   │                     │
│  │ Files: 24h      │  │ VCs/VPs: 60s     │                     │
│  └────────┬────────┘  └───────┬──────────┘                     │
│           │                   │                                 │
│           ▼                   ▼                                 │
│  ┌─────────────────────────────────────────┐                   │
│  │      RECONCILIATION LAYER               │                   │
│  │                                         │                   │
│  │  - Upsert by consensus_timestamp        │                   │
│  │  - Merge Guardian API enrichments       │                   │
│  │  - Track data_source                    │                   │
│  │  - Auto-update search_vector (trigger)  │                   │
│  └────────────────┬────────────────────────┘                   │
│                   │                                             │
│                   ▼                                             │
│  ┌─────────────────────────────────────────┐                   │
│  │      PostgreSQL                         │                   │
│  │                                         │                   │
│  │  message, *_analytics, *_cache          │                   │
│  │  guardian_*_state (API-sourced)          │                   │
│  │  ipfs_files                             │                   │
│  │  Materialized views                     │                   │
│  └─────────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Guardian API Poller Service

```
Endpoints to Poll     Frequency    Incremental Strategy
───────────────────   ──────────   ──────────────────────────
GET /policies         60 seconds   Query param: ?updatedAfter=<lastSync>
GET /schemas          120 seconds  Query param: ?updatedAfter=<lastSync>
GET /tokens           120 seconds  Query param: ?updatedAfter=<lastSync>
GET /profiles         300 seconds  Full sync (small dataset)
GET /vc-documents     60 seconds   Query param: ?updatedAfter=<lastSync>
                                   (paginated, process in batches)
GET /vp-documents     60 seconds   Same as VCs
```

**Incremental strategy:**
- Store `last_synced_at` per entity type in `synchronization_task` table
- Use `updatedAfter` query parameter if Guardian API supports it
- Fall back to full pagination with client-side deduplication if not
- Batch upserts using PostgreSQL `INSERT ... ON CONFLICT ... DO UPDATE`

**Authentication:**
```
Environment Variable: GUARDIAN_API_URL=http://guardian-api:3000
Environment Variable: GUARDIAN_API_TOKEN=<service-account-token>
Environment Variable: GUARDIAN_API_ENABLED=true|false
```

### 6.3 Mirror Node Poller (Improved)

Same as current architecture but writes directly to PostgreSQL:
- `TopicService` → writes to `message_cache` and `topic_cache` tables
- `MessageService` → parses and upserts into `message` table
- `TokenService` → writes to `token_cache` and `nft_cache` tables
- `FileService` → writes to `ipfs_files` table (replaces GridFS)

**Improvement:** Use PostgreSQL's `INSERT ... ON CONFLICT` for idempotent upserts instead of the current find-then-update pattern.

### 6.4 Enrichment Redesign

The 16 cron synchronizers are replaced by:

1. **PostgreSQL triggers** — auto-update `search_vector` on insert/update
2. **Materialized view refreshes** — replace the count-based analytics
3. **Lightweight enrichment jobs** — only for data that requires IPFS parsing (policy ZIP analysis, schema extraction)

```
Current enrichment (SLOW):
  Load ALL policies → Load ALL SRs → Load ALL topics →
  Load ALL documents (count per topic) → Load ALL tokens →
  Iterate all policies → update analytics

New enrichment (FAST):
  1. search_vector: auto-updated by trigger on INSERT/UPDATE
  2. policy_analytics: computed by INSERT trigger or lightweight cron
     - Parse policy ZIP → extract tools, tokens
     - Compute hash
     - Link to registry via topic hierarchy (single JOIN query)
  3. document_analytics: computed on message INSERT
     - Link VC to policy: JOIN message ON topic_id chain
     - Link VC to schema: JOIN by IPFS CID
  4. Materialized views: REFRESH CONCURRENTLY every 60 seconds
```

### 6.5 Data Reconciliation

```sql
-- Upsert from Mirror Node (authoritative for on-chain fields)
INSERT INTO message (consensus_timestamp, topic_id, type, action, owner, ...)
VALUES (:ct, :topic, :type, :action, :owner, ...)
ON CONFLICT (consensus_timestamp) DO UPDATE SET
    status = EXCLUDED.status,
    files = EXCLUDED.files,
    documents = EXCLUDED.documents,
    loaded = EXCLUDED.loaded,
    last_update = EXCLUDED.last_update,
    data_source = CASE
        WHEN message.data_source = 'guardian_api' THEN 'both'
        ELSE 'mirror_node'
    END,
    updated_at = NOW();

-- Merge from Guardian API (authoritative for internal state)
INSERT INTO guardian_policy_state (policy_message_id, status, policy_tag, ...)
VALUES (:msg_id, :status, :tag, ...)
ON CONFLICT (policy_message_id) DO UPDATE SET
    status = EXCLUDED.status,
    policy_roles = EXCLUDED.policy_roles,
    last_synced_at = NOW();
```

---

## 7. E. Performance Advantages

### 7.1 Specific Queries That Become Dramatically Faster

| Query | MongoDB (Current) | PostgreSQL (Proposed) | Speedup |
|---|---|---|---|
| **Registry detail** (9 counts) | 9 sequential `count()` + 2 `findOne()` | 1 `SELECT` from `mv_registry_activity` | **~10x** |
| **Policy detail** (8 counts) | 8 sequential `count()` | 1 `SELECT` from `mv_policy_activity` | **~8x** |
| **Topic detail** (13 counts) | 13 sequential `count()` | 1 `SELECT` from `mv_topic_activity` | **~13x** |
| **Full-text search** | `$regex` — full collection scan O(n) | `tsvector` GIN index — O(log n) | **100x+** at scale |
| **NFT list** (cross-collection join) | Fetch NFTs, then fetch Messages by timestamp array | Single `JOIN nft_cache ON message` | **~3x** |
| **Relationship graph** | Recursive N+1 `findOne()` per hop | Single recursive CTE | **~5x** (depth-dependent) |
| **VC list with policy filter** | Regex match on `analytics.policyId` | Index scan on `document_analytics.policy_id` | **~10x** |
| **Registry users** | Load ALL registries to get topicIds, then filter DIDs | `JOIN` on registrant_topic_id | **~5x** |
| **Policy sync** (enrichment) | Load ALL entities into memory, iterate | `INSERT INTO policy_analytics SELECT ... JOIN ...` | **~50x** |
| **Landing analytics** | Read from `analytics` collection (cron-populated) | `SELECT` from `mv_landing_analytics` (refreshable) | Similar speed, but **always fresh** |

### 7.2 Materialized View Refresh Strategy

```
View                        Refresh Frequency    Concurrent?
─────────────────────────   ────────────────     ──────────
mv_registry_activity        60 seconds           Yes (has unique index)
mv_policy_activity          60 seconds           Yes
mv_topic_activity           120 seconds          Yes
mv_landing_analytics        300 seconds          Yes
```

Use `REFRESH MATERIALIZED VIEW CONCURRENTLY` to allow reads during refresh. This requires a unique index on the view, which all views above have.

### 7.3 Connection Pooling Strategy

```
                    ┌──────────────────────┐
                    │    PgBouncer         │
                    │    (connection pool)  │
                    │                      │
                    │  Mode: transaction   │
                    │  Pool size: 20       │
                    │  Max clients: 100    │
                    └──────────┬───────────┘
                               │
            ┌──────────────────┼──────────────────┐
            │                  │                   │
    ┌───────▼──────┐  ┌───────▼──────┐  ┌────────▼──────┐
    │ indexer-      │  │ indexer-     │  │ indexer-api-  │
    │ worker        │  │ service     │  │ gateway       │
    │ (writes)      │  │ (reads +    │  │ (reads via    │
    │               │  │  enrichment)│  │  NATS)        │
    │ Pool: 5       │  │ Pool: 10   │  │ Pool: 5       │
    └──────────────┘  └─────────────┘  └───────────────┘
```

**MikroORM PostgreSQL configuration:**
```typescript
// Replace MongoDriver with PostgreSqlDriver
import { PostgreSqlDriver } from '@mikro-orm/postgresql';

export const COMMON_CONNECTION_CONFIG = {
    driver: PostgreSqlDriver,
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '5432'),
    dbName: process.env.GUARDIAN_ENV
        ? `${process.env.GUARDIAN_ENV}_${process.env.HEDERA_NET}_${process.env.DB_DATABASE}`
        : process.env.DB_DATABASE,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    pool: {
        min: 2,
        max: 10,
    },
    entities: ['dist/entity/*.js'],
};
```

### 7.4 Eliminating the Enrichment Bottleneck

Current enrichment (e.g., `synchronize-policy.ts`) loads **every policy, every SR, every topic, every document count, and every token** into memory. For a large instance this is:
- ~1000 policies x full document scan
- ~100 SRs
- ~5000 topics
- ~500,000 VC/VP documents (for counting)
- ~2000 tokens

With PostgreSQL, the entire policy analytics computation becomes:

```sql
INSERT INTO policy_analytics (message_id, consensus_timestamp, registry_id, vc_count, vp_count, ...)
SELECT
    p.id,
    p.consensus_timestamp,
    sr.consensus_timestamp AS registry_id,
    COALESCE(doc_counts.vc_count, 0),
    COALESCE(doc_counts.vp_count, 0),
    ...
FROM message p
LEFT JOIN message topic ON topic.topic_id = p.topic_id
    AND topic.type = 'Topic' AND topic.action = 'create-topic'
LEFT JOIN message sr ON sr.options->>'registrantTopicId' = topic.options->>'parentId'
    AND sr.type = 'Standard Registry'
LEFT JOIN (
    SELECT da.policy_id,
           COUNT(*) FILTER (WHERE m.type = 'VC-Document') AS vc_count,
           COUNT(*) FILTER (WHERE m.type = 'VP-Document') AS vp_count
    FROM document_analytics da
    JOIN message m ON m.consensus_timestamp = da.consensus_timestamp
    GROUP BY da.policy_id
) doc_counts ON doc_counts.policy_id = p.consensus_timestamp
WHERE p.type = 'Instance-Policy' AND p.action = 'publish-policy'
ON CONFLICT (consensus_timestamp) DO UPDATE SET
    registry_id = EXCLUDED.registry_id,
    vc_count = EXCLUDED.vc_count,
    vp_count = EXCLUDED.vp_count,
    updated_at = NOW();
```

This replaces hundreds of thousands of in-memory iterations with a **single SQL statement** executed entirely within the database engine.

---

## 8. Migration Strategy

### 8.1 Phase 1: Dual-Write (Weeks 1-3)
- Deploy PostgreSQL alongside MongoDB
- Modify worker to write to both databases
- Verify data consistency

### 8.2 Phase 2: Read Migration (Weeks 3-5)
- Switch `indexer-service` query handlers to read from PostgreSQL
- Keep MongoDB as fallback
- Performance benchmarking

### 8.3 Phase 3: Guardian API Integration (Weeks 5-8)
- Implement Guardian API poller
- Add `guardian_*_state` tables
- Implement reconciliation layer

### 8.4 Phase 4: Cutover (Weeks 8-10)
- Remove MongoDB writes
- Remove cron synchronizers replaced by materialized views
- Production monitoring

### 8.5 Data Migration Script

```sql
-- One-time migration from MongoDB export (JSON) to PostgreSQL
-- Use pg_bulk_load or COPY FROM for performance
-- Estimated: ~500K messages at 10K/sec = ~50 seconds

COPY message (consensus_timestamp, topic_id, type, action, ...)
FROM '/data/export/messages.csv' WITH CSV HEADER;

-- Rebuild search vectors
UPDATE message SET search_vector = build_search_vector(message.*);

-- Initial materialized view population
REFRESH MATERIALIZED VIEW mv_registry_activity;
REFRESH MATERIALIZED VIEW mv_policy_activity;
REFRESH MATERIALIZED VIEW mv_topic_activity;
```

---

## Key File References

| File | Relevance |
|---|---|
| `indexer-common/src/entity/message.ts` | Central entity — polymorphic Message with analytics/options |
| `indexer-common/src/entity/message-cache.ts` | Raw ingestion buffer |
| `indexer-common/src/entity/analytics.ts` | Daily aggregate snapshots |
| `indexer-common/src/entity/token-cache.ts` | Token sync state |
| `indexer-common/src/entity/nft-cache.ts` | NFT metadata |
| `indexer-common/src/entity/topic-cache.ts` | Topic sync watermarks |
| `indexer-common/src/entity/project-coordinates.ts` | Geo data |
| `indexer-common/src/entity/priority-queue.ts` | On-demand loading |
| `indexer-common/src/entity/synchronization-task.ts` | Job locks |
| `indexer-common/src/db-helper/db-config.ts` | MongoDB/MikroORM config |
| `indexer-service/src/api/entities.service.ts` | **Core query patterns** — all N+1 queries |
| `indexer-service/src/api/search.service.ts` | Full-text search with $regex |
| `indexer-service/src/api/landing.service.ts` | Landing analytics queries |
| `indexer-service/src/helpers/synchronizers/synchronize-all.ts` | 16 enrichment synchronizers |
| `indexer-service/src/helpers/synchronizers/synchronize-policy.ts` | Policy enrichment (most complex) |
| `indexer-service/src/helpers/synchronizers/synchronize-vcs.ts` | VC enrichment pattern |
| `indexer-service/src/helpers/text-search-options.ts` | textSearch concatenation logic |
| `indexer-service/src/utils/relationships.ts` | Recursive relationship graph |
| `indexer-service/src/utils/parse-page-params.ts` | Pagination utility |
| `indexer-api-gateway/src/api/services/entities.ts` | REST endpoint definitions |
| `indexer-api-gateway/src/api/services/search.ts` | Search REST endpoint |
| `indexer-api-gateway/src/api/services/landing.ts` | Landing/analytics REST |
| `indexer-api-gateway/src/api/services/analytics.ts` | Analytics REST (policy comparison, derivations) |
| `indexer-api-gateway/src/api/services/filters.ts` | Filter REST (currently returns null) |
| `indexer-interfaces/src/types/message-type.type.ts` | All 30+ MessageType values |
| `indexer-interfaces/src/types/message-action.type.ts` | All MessageAction values |
| `api-gateway/src/api/service/policy.ts` | Guardian API policy endpoints (dual-source) |
| `api-gateway/src/api/service/profile.ts` | Guardian API profile endpoints (dual-source) |
| `api-gateway/src/api/service/tokens.ts` | Guardian API token endpoints (dual-source) |
| `api-gateway/src/api/service/schema.ts` | Guardian API schema endpoints (dual-source) |
| `api-gateway/src/api/service/account.ts` | Guardian API account endpoints (dual-source) |
| `common/src/entity/policy.ts` | Guardian internal Policy model (richer than indexed) |
| `common/src/entity/vc-document.ts` | Guardian internal VC model (has approval state) |
| `common/src/entity/vp-document.ts` | Guardian internal VP model |

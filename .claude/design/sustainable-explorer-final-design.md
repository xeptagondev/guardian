# Sustainable Explorer -- Final Architecture Design

**Date:** 2026-03-20<br>
**Status:** Pending Approval<br>
**Version:** 1.0

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Tech Stack](#3-tech-stack)
4. [Data Sources](#4-data-sources)
5. [Data Pipeline (BullMQ Queues)](#5-data-pipeline-bullmq-queues)
6. [PostgreSQL Schema](#6-postgresql-schema)
7. [Business Data Mapping](#7-business-data-mapping)
8. [Caching Strategy (Redict)](#8-caching-strategy-redict)
9. [API Design](#9-api-design)
10. [Frontend Architecture](#10-frontend-architecture)
11. [Code Reuse Plan](#11-code-reuse-plan)
12. [Configuration](#12-configuration)
13. [Docker Compose](#13-docker-compose)
14. [Project Structure](#14-project-structure)
15. [Development Phases](#15-development-phases)

---

## 1. Executive Summary

**Sustainable Explorer** is a standalone application that indexes Hedera Guardian blockchain data and presents it through a sustainability-focused lens. It transforms raw HCS (Hedera Consensus Service) messages and IPFS documents into business-domain entities: Projects, Credits, Methodologies, Organizations, and Retirements.

Unlike the existing Guardian Indexer (which is tightly coupled to the Guardian ecosystem via NATS, MongoDB, and 5 co-dependent services), Sustainable Explorer is a self-contained service that supports two deployment modes:

**Mode 1 — Standalone:** Connects to any Hedera network using only public data sources (Mirror Node + IPFS). No Guardian instance required.

**Mode 2 — Co-located with Guardian:** Optionally connects to a Guardian REST API for faster published data ingestion, and can share existing Redict infrastructure. Guardian API provides already-parsed documents instantly, bypassing the blockchain consensus + IPFS fetch delay.

Data sources:
- **Hedera Mirror Node REST API** -- public, no authentication (always enabled)
- **IPFS Gateways** -- public, no authentication (always enabled)
- **Guardian REST API** -- JWT-authenticated, published data only (optional, controlled by `GUARDIAN_API_URL`)

The application uses **PostgreSQL** for structured storage with materialized views and full-text search, **Redict** (Redis-compatible, own or shared with Guardian) for job queues and caching, and **BullMQ** for reliable job processing with retry, priority, and concurrency control.

**Core tech stack:** NestJS (API + Worker), PostgreSQL 16, Redict 7, BullMQ 5, Vue 3 + Nuxt 3 + TanStack.

---

## 2. Architecture Overview

### 2.1 Two Deployment Modes

Sustainable Explorer supports two deployment modes. The same codebase runs in both — Guardian API integration is controlled by environment variables.

**Mode 1 — Standalone (remote node):** Connect to any Hedera network using only public endpoints. No Guardian instance required.

**Mode 2 — Co-located (with Guardian cluster):** Optionally connect to a Guardian API for faster published data, and share existing Redict infrastructure.

```
     MODE 1: STANDALONE                    MODE 2: CO-LOCATED WITH GUARDIAN
     (public data only)                    (+ optional Guardian API accelerator)

  +------------------+                  +------------------+   +-------------------+
  | Mirror Node API  |                  | Mirror Node API  |   | Guardian API      |
  | (public, no auth)|                  | (public, no auth)|   | (JWT auth)        |
  +--------+---------+                  +--------+---------+   | GET /policies     |
           |                                     |             | GET /schemas      |
  +--------+---------+                           |             | GET /tokens       |
  | IPFS Gateways    |                  +--------+---------+   | (published only)  |
  | (public, no auth)|                  | IPFS Gateways    |   +--------+----------+
  +--------+---------+                  +--------+---------+            |
           |                                     |                      |
           +------+                              +----------+-----------+
                  |                                         |
  +---------------v-----------+          +------------------v-----------------+
  | SUSTAINABLE EXPLORER      |          | SUSTAINABLE EXPLORER               |
  |                           |          |                                    |
  | Worker(s):                |          | Worker(s):                         |
  |  mirror-node-* queues     |          |  mirror-node-* queues              |
  |  ipfs-files queue         |          |  guardian-api-sync queue (NEW)     |
  |  maintenance/* queues     |          |  ipfs-files queue                  |
  |                           |          |  maintenance/* queues              |
  | API Server:               |          |                                    |
  |  REST + SSE               |          | API Server:                        |
  |                           |          |  REST + SSE                        |
  | +----------+ +----------+ |          |                                    |
  | |PostgreSQL| | Redict   | |          | +----------+ +----------+         |
  | |(own)     | | (own)    | |          | |PostgreSQL| | Redict   |         |
  | +----------+ +----------+ |          | |(own)     | | (shared  |         |
  +---------------------------+          | |          | |  with    |         |
                                         | |          | |  Guardian)|        |
                                         | +----------+ +----------+         |
                                         +-----------------------------------+
```

### 2.2 Why Guardian API Integration Matters

When a policy is published in Guardian, the full document is **immediately available** in Guardian's database. The Mirror Node path requires: blockchain consensus → Mirror Node indexing → worker fetches HCS message → IPFS fetch → parse. This can take **minutes**.

| Data | Mirror Node Path | Guardian API Path | Speed |
|------|-----------------|-------------------|-------|
| Published policy (full config) | HCS msg → IPFS fetch → parse ZIP | `GET /policies?status=PUBLISHED` | Minutes → seconds |
| Published schema (full JSON-LD) | HCS msg → IPFS fetch → parse | `GET /schemas?status=PUBLISHED` | Minutes → seconds |
| Minted VCs | HCS msg → IPFS fetch → parse | Policy block data API | Minutes → seconds |
| Token metadata + policy links | Mirror Node → separate fetch | `GET /tokens` (includes policyIds) | Seconds → instant |
| Published modules/tools | HCS msg → IPFS fetch | `GET /modules`, `GET /tools` | Minutes → seconds |

Guardian API gives **already-parsed, already-assembled** documents — no IPFS fetch, no multi-chunk reassembly, no ZIP extraction needed.

### 2.3 Data Source Precedence

When Guardian API is enabled, data arrives from two sources. Reconciliation rules:

1. **Guardian API data arrives first** — inserted into PostgreSQL with `data_source = 'guardian_api'`
2. **Mirror Node data arrives later** — upserts with `data_source = 'mirror_node'` or `'both'`
3. **Mirror Node is always authoritative** for: consensus timestamps, sequence numbers, token supply
4. **Guardian API is authoritative** for: document content (already parsed, no IPFS needed)
5. **IPFS is the fallback** for document content: if Guardian API is not configured, or if a document was not available from Guardian API (e.g., third-party data), the worker fetches the document from IPFS gateways using the CIDs found in the HCS message
6. **Deduplication** by `consensus_timestamp` — if a record already exists from Guardian API, Mirror Node upsert enriches it with blockchain-verified fields. If document content already exists (from Guardian API), the IPFS fetch is skipped for that CID

**Document content resolution order:**
```
1. Check PostgreSQL: does message.documents already have content?
   YES → skip (already populated by Guardian API or previous IPFS fetch)
   NO  ↓
2. Is Guardian API enabled and is this a self-org message?
   YES → fetch from Guardian API (fast, already parsed)
   NO  ↓
3. Fetch from IPFS gateways (slow, retry with backoff)
   SUCCESS → store in ipfs_files table + update message.documents
   FAIL    → dead letter queue, retry on next cycle
```

### 2.4 Core Architecture

```
     +-----------------------------v-------------------------------+
     |                    SUSTAINABLE EXPLORER                     |
     |                                                             |
     |  +-------------------+          +------------------------+  |
     |  |   API Server      |          |   Worker(s)            |  |
     |  |   (NestJS)        |          |   (NestJS + BullMQ)    |  |
     |  |                   |          |                        |  |
     |  |  REST endpoints   |          |  mirror-node-topics    |  |
     |  |  SSE events       |          |  mirror-node-messages  |  |
     |  |  Cache reads      |          |  mirror-node-tokens    |  |
     |  |  DB queries       |          |  ipfs-files            |  |
     |  |                   |          |  guardian-api-sync     |  |
     |  |                   |          |  maintenance/*         |  |
     |  +--------+----------+          +-----------+------------+  |
     |           |                                 |               |
     |           +----------------+----------------+               |
     |                            |                                |
     |              +-------------v--------------+                 |
     |              |         Redict             |                 |
     |              |   (Redis-compatible)       |                 |
     |              |                            |                 |
     |              |  - BullMQ job queues       |                 |
     |              |  - Response cache          |                 |
     |              |  - Pub/Sub for SSE         |                 |
     |              |  (own instance OR shared   |                 |
     |              |   with Guardian cluster)   |                 |
     |              +----------------------------+                 |
     |                            |                                |
     |              +-------------v--------------+                 |
     |              |       PostgreSQL 16        |                 |
     |              |                            |                 |
     |              |  - Normalized tables       |                 |
     |              |  - Materialized views      |                 |
     |              |  - tsvector search         |                 |
     |              |  - JSONB flexible fields   |                 |
     |              |  - Recursive CTEs          |                 |
     |              +----------------------------+                 |
     +-------------------------------------------------------------+
```

**Key architectural decisions:**

- **Two processes:** API Server and Worker share the same NestJS codebase but run different modules. The API handles HTTP requests; the Worker processes BullMQ jobs.
- **Redict** serves triple duty: BullMQ persistence, response caching, and Pub/Sub for SSE event delivery. Can be its own instance or shared with an existing Guardian cluster.
- **PostgreSQL** is the single source of truth. All business logic is expressed as SQL (materialized views, triggers, recursive CTEs).
- **Guardian API** is an optional accelerator. When enabled, a `guardian-api-sync` BullMQ queue polls the Guardian API for published data, providing faster ingestion without waiting for blockchain finality + IPFS.
- **No NATS.** Inter-process communication is handled by BullMQ (job dispatch) and Redict Pub/Sub (event notification).

---

## 3. Tech Stack

| Technology | Version | Purpose |
|---|---|---|
| Node.js | 20 LTS | Runtime |
| NestJS | 11.x | API framework + Worker framework |
| TypeScript | 5.5+ | Language |
| PostgreSQL | 16.x | Primary datastore |
| Redict | 7.x | Cache, job queue backend, Pub/Sub |
| BullMQ | 5.x | Job queue management |
| TypeORM | 0.3.x | PostgreSQL ORM with migration support |
| Vue 3 | 3.5+ | Frontend framework |
| Nuxt 3 | 3.x | SSR framework (file-based routing, SSR, code splitting) |
| TanStack Query | 5.x | Data fetching, caching, background refresh |
| TanStack Table | 8.x | Headless data tables with sorting/filtering/pagination |
| Docker | 24+ | Containerization |
| Docker Compose | 2.x | Local orchestration |
| nginx | 1.25+ | Frontend static serving + API proxy |

**Why these choices:**

- **TypeORM over MikroORM:** Better PostgreSQL support (native migrations, query builder, materialized view support). The existing indexer uses MikroORM with MongoDB driver; we are not constrained by that choice.
- **Redict over Redis:** Open-source fork (LGPL-3.0), fully compatible with Redis protocol and all Redis client libraries. Drop-in replacement.
- **BullMQ over custom Jobs system:** The existing indexer uses a hand-rolled `Job`/`Jobs` polling loop. BullMQ provides retry with exponential backoff, timeout, concurrency control, priority queues, dead letter queues, job deduplication, persistence across restarts, and multi-instance distribution out of the box.

---

## 4. Data Sources

### 4.1 Hedera Mirror Node REST API

The Mirror Node is the primary data source. It provides blockchain-verified data from any Hedera network.

**Base URLs:**
- Mainnet: `https://mainnet.mirrornode.hedera.com`
- Testnet: `https://testnet.mirrornode.hedera.com`
- Previewnet: `https://previewnet.mirrornode.hedera.com`
- Custom: configurable via `HEDERA_MIRROR_NODE_URL`

**Endpoints used:**

| Endpoint | Purpose | Polling Strategy |
|---|---|---|
| `GET /api/v1/topics/{topicId}/messages` | Fetch HCS messages for a topic | Paginated, track `sequenceNumber` watermark per topic |
| `GET /api/v1/topics/{topicId}/messages?sequencenumber=gt:{n}` | Incremental fetch (new messages only) | From last known sequence number |
| `GET /api/v1/tokens/{tokenId}` | Token metadata (name, symbol, supply, type) | On discovery + periodic refresh |
| `GET /api/v1/tokens/{tokenId}/nfts` | NFT serial enumeration | Paginated, track `serialNumber` watermark |
| `GET /api/v1/tokens/{tokenId}/nfts/{serial}/transactions` | NFT transaction history (transfers, mints) | On demand |

**Rate limits:**
- Public endpoints: ~50 requests/second (no API key)
- With API key: configurable higher limits
- The worker respects rate limits via BullMQ concurrency settings and configurable delays between requests

**Authentication:** None required. All endpoints are public.

**Data format:** All responses are JSON. HCS message content is base64-encoded in the `message` field.

### 4.2 IPFS Gateways

IPFS stores the actual document content referenced by HCS messages. Each message contains one or more IPFS CIDs (Content Identifiers) in its decoded payload.

**Gateway URLs (configurable, tried in order):**
1. `https://ipfs.io/ipfs/{cid}`
2. `https://cloudflare-ipfs.com/ipfs/{cid}`
3. `https://gateway.pinata.cloud/ipfs/{cid}`

**Content types fetched:**
- JSON-LD Verifiable Credentials and Presentations
- JSON Schema definitions
- ZIP archives (policy configurations)
- Binary files (attached documents)

**Reliability considerations:**
- IPFS fetches are unreliable (timeouts, 404s, slow gateways)
- BullMQ retry with exponential backoff (5 attempts, starting at 30s)
- 3-minute timeout per fetch
- Files are stored in PostgreSQL `ipfs_files` table after successful fetch (no re-fetching)
- Multiple gateways tried in sequence on failure

**Authentication:** None required.

### 4.3 Guardian API (Optional — Co-located Mode)

When running alongside a Guardian instance, the Explorer can optionally connect to the Guardian REST API to get **published data faster**. This eliminates the blockchain consensus + Mirror Node indexing + IPFS fetch delay for the connected Guardian's own data.

**Enabled by:** Setting `GUARDIAN_API_URL` environment variable. When not set, this source is completely disabled and the Explorer runs in standalone mode.

**Base URL:** `http://api-gateway:3000` (or any reachable Guardian API)

**Endpoints polled (published data only):**

| Endpoint | Purpose | Polling Frequency |
|---|---|---|
| `GET /policies?pageSize=100` | Published policies with full config | 30 seconds |
| `GET /schemas?pageSize=100&status=PUBLISHED` | Published schemas with full JSON-LD | 60 seconds |
| `GET /tokens` | Token metadata with policy associations | 60 seconds |
| `GET /modules?pageSize=100&status=PUBLISHED` | Published modules | 120 seconds |
| `GET /tools?pageSize=100&status=PUBLISHED` | Published tools | 120 seconds |

**What you get that Mirror Node doesn't give directly:**
- Full policy configuration (block tree, navigation) — already parsed, no ZIP extraction
- Full schema JSON-LD — already assembled, no IPFS fetch
- Token-to-policy associations — cross-reference that only Guardian knows
- Complete VC/VP documents — already parsed, no IPFS fetch

**Authentication:**

Guardian API requires JWT auth. The Explorer uses a dedicated read-only user:

```
1. On startup: POST /accounts/login → get refreshToken (1 year TTL)
2. Every 50 seconds: POST /accounts/access-token → get accessToken (60s TTL)
3. All API calls: Authorization: Bearer <accessToken>
```

Configuration:
```
GUARDIAN_API_URL=http://api-gateway:3000      # Guardian API base URL (empty = disabled)
GUARDIAN_API_USERNAME=sustainable-explorer     # Dedicated read-only user
GUARDIAN_API_PASSWORD=<from-env>              # User password
```

**The auth token manager** is a small service that:
- Logs in once on startup, stores the refresh token
- Auto-refreshes the access token every 50 seconds (before 60s expiry)
- Retries login on auth failures
- All Guardian API calls go through this manager

**Incremental strategy:**
- Store `last_synced_at` per entity type in `synchronization_task` table
- Page through results, compare with existing PostgreSQL records by `consensus_timestamp`
- Upsert with `data_source = 'guardian_api'`
- When Mirror Node data arrives later, it enriches the record and sets `data_source = 'both'`

**Failure handling:**
- If Guardian API is unreachable, the Explorer continues with Mirror Node only
- No data loss — Mirror Node is always the fallback
- Guardian API sync jobs go to dead letter queue after 3 failures, auto-retry on next cycle

### 4.4 Redict (Shared or Own Instance)

When co-located with a Guardian cluster, the Explorer can share the existing Redict instance:

```
REDICT_URL=redis://redict:6379     # Shared Guardian Redict
REDICT_DB=1                        # Use a separate database number (Guardian uses 0)
REDICT_KEY_PREFIX=se:              # Namespace all keys to avoid collisions
```

When running standalone:
```
REDICT_URL=redis://redict:6379     # Own Redict instance
REDICT_DB=0
REDICT_KEY_PREFIX=se:
```

BullMQ queues, cache keys, and Pub/Sub channels are all prefixed with `se:` to coexist safely with Guardian's own Redict usage.

---

## 5. Data Pipeline (BullMQ Queues)

All data ingestion is managed through BullMQ queues. Each queue has dedicated processors with configured concurrency, retry, and timeout settings.

### 5.1 Queue Definitions

#### `mirror-node-topics`

Fetches HCS messages from Mirror Node topics.

| Setting | Value |
|---|---|
| Concurrency | 5 |
| Max retries | 3 |
| Backoff | Exponential, 10s initial |
| Timeout | 2 minutes |
| Rate limit | 10 jobs per second (group) |
| Priority | 1 (org topics), 10 (network topics) |

**Job payload:**
```typescript
interface TopicSyncJob {
  topicId: string;           // e.g. "0.0.1234"
  fromSequenceNumber: number; // watermark: last fetched + 1
  isOrgTopic: boolean;       // determines priority
}
```

**Processing logic:**
1. Fetch `GET /api/v1/topics/{topicId}/messages?sequencenumber=gt:{n}&limit=100`
2. For each message: decode base64, insert into `message_cache` table
3. Update `topic_cache.messages` watermark
4. If response has `links.next`, enqueue self with updated watermark
5. For each new message, enqueue a `mirror-node-messages` job

#### `mirror-node-messages`

Parses raw cached messages into the `message` table. Handles multi-chunk message assembly, IPFS CID extraction, and type classification.

| Setting | Value |
|---|---|
| Concurrency | 10 |
| Max retries | 3 |
| Backoff | Fixed, 5s |
| Timeout | 1 minute |

**Job payload:**
```typescript
interface MessageProcessJob {
  consensusTimestamp: string;
  topicId: string;
}
```

**Processing logic:**
1. Read raw message from `message_cache`
2. Parse JSON content (using ported `parser.ts` logic)
3. Handle multi-chunk assembly (match by `chunkId`, wait for all `chunkTotal` parts)
4. Classify message type and action
5. Extract IPFS CIDs from `files` field
6. Upsert into `message` table (trigger auto-updates `search_vector`)
7. For each IPFS CID, enqueue an `ipfs-files` job (deduplicated by CID)
8. If message is a Topic type, discover child topic and enqueue `mirror-node-topics`
9. If message is a Token type, enqueue `mirror-node-tokens`

#### `mirror-node-tokens`

Fetches token metadata and NFT serial data.

| Setting | Value |
|---|---|
| Concurrency | 2 |
| Max retries | 3 |
| Backoff | Exponential, 10s initial |
| Timeout | 2 minutes |

**Job payload:**
```typescript
interface TokenSyncJob {
  tokenId: string;
  fetchNfts: boolean;
  fromSerial: number;
}
```

**Processing logic:**
1. Fetch `GET /api/v1/tokens/{tokenId}` for metadata
2. Upsert into `token_cache`
3. If NFT type and `fetchNfts=true`, paginate through `GET /api/v1/tokens/{tokenId}/nfts`
4. Upsert each NFT into `nft_cache`

#### `ipfs-files`

Fetches document content from IPFS gateways and stores in PostgreSQL.

| Setting | Value |
|---|---|
| Concurrency | 3 |
| Max retries | 5 |
| Backoff | Exponential, 30s initial, 2x factor |
| Timeout | 3 minutes |
| Deduplication | By CID (skip if already in `ipfs_files` table) |

**Job payload:**
```typescript
interface IpfsFileJob {
  cid: string;
  messageTimestamp: string; // which message referenced this CID
}
```

**Processing logic:**
1. Check if CID already exists in `ipfs_files` -- skip if so
2. Try each gateway in order until success
3. Store content as BYTEA in `ipfs_files` table
4. Parse content if JSON (VC, VP, Schema) and update `message.documents` JSONB
5. On total failure (all retries exhausted), log to dead letter queue and `logs` table

#### `guardian-api-sync` (Optional — only when `GUARDIAN_API_URL` is set)

Polls the Guardian REST API for published data. Provides faster ingestion than the Mirror Node path by getting already-parsed documents directly from Guardian's database.

| Setting | Value |
|---|---|
| Concurrency | 1 |
| Max retries | 3 |
| Backoff | Fixed, 30s |
| Timeout | 2 minutes |
| Repeat | Every 30 seconds (policies), 60 seconds (schemas/tokens), 120 seconds (modules/tools) |
| Enabled | Only when `GUARDIAN_API_URL` is configured |

**Job payload:**
```typescript
interface GuardianApiSyncJob {
  entityType: 'policies' | 'schemas' | 'tokens' | 'modules' | 'tools';
  lastSyncedAt: string;   // ISO timestamp for incremental fetch
}
```

**Processing logic:**
1. Acquire access token from `GuardianAuthManager` (auto-refreshes every 50s)
2. Fetch `GET /policies?pageSize=100` (or schemas, tokens, etc.)
3. For each entity, extract the `consensus_timestamp` (messageId) if available
4. Upsert into `message` table with `data_source = 'guardian_api'`:
   - Policy: insert with full config, block tree, tokens, schemas — **no IPFS fetch needed**
   - Schema: insert with full JSON-LD — **no IPFS fetch needed**
   - Token: insert with policy associations
5. Store parsed documents directly in `message.documents` JSONB — **skips the IPFS pipeline entirely**
6. Update `synchronization_task.last_synced_at` for this entity type
7. Publish `GUARDIAN_DATA_SYNCED` via Redict Pub/Sub → triggers cache invalidation + SSE push

**Key advantage:** When Mirror Node data arrives later for the same `consensus_timestamp`, the record already exists with full document content. The Mirror Node upsert only adds blockchain-verified fields (sequence number, authoritative timestamp) and sets `data_source = 'both'`.

**Failure handling:**
- If Guardian API returns 401/403: re-login and retry
- If Guardian API is unreachable: log warning, skip this cycle, Mirror Node continues independently
- After 3 consecutive failures: pause Guardian sync for 5 minutes, then retry
- Explorer never depends on Guardian API — it's purely an accelerator

#### `maintenance/refresh-materialized-views`

Periodic refresh of all materialized views.

| Setting | Value |
|---|---|
| Concurrency | 1 (singleton) |
| Repeat | Every 60 seconds |
| Timeout | 5 minutes |

**Processing logic:**
```sql
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_registry_activity;
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_policy_activity;
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_topic_activity;
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_landing_analytics;
```

#### `maintenance/build-business-views`

Builds/refreshes the business domain mapping (Projects, Credits, etc.) from raw messages.

| Setting | Value |
|---|---|
| Concurrency | 1 |
| Triggered | After sync batch completes (via BullMQ flow) |
| Timeout | 10 minutes |

**Processing logic:**
1. Query messages with type VC-Document that have project/credit schemas
2. Map to business entities using schema analysis
3. Upsert into `business_view` table
4. Publish cache invalidation via Redict Pub/Sub
5. Send SSE event notification

### 5.2 Organization Prioritization

When `ORG_ROOT_TOPIC_ID` is set, the worker discovers the full topic tree for that organization and marks all topics for high-priority processing.

**Discovery process:**
1. On startup, read `ORG_ROOT_TOPIC_ID` from config
2. Fetch root topic messages
3. Find all child topic messages (type=Topic, action=create-topic)
4. Recursively discover sub-topics
5. Store all discovered topic IDs in `organization_config` table
6. All jobs for these topics get BullMQ priority 1 (highest)
7. Network-wide topic discovery jobs get priority 10 (lower)

**Priority enforcement:**
```typescript
// When enqueuing a topic sync job:
const isOrgTopic = await orgConfigService.isOrgTopic(topicId);
await topicQueue.add('sync-topic', payload, {
  priority: isOrgTopic ? 1 : 10,
  jobId: `topic-${topicId}`, // deduplication
});
```

---

## 6. PostgreSQL Schema

### 6.1 Enums

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

CREATE TYPE processing_status AS ENUM ('LOADING', 'LOADED', 'ERROR');
CREATE TYPE priority_status AS ENUM ('WAITING', 'PROCESSING', 'DONE', 'ERROR');
CREATE TYPE token_type AS ENUM ('FUNGIBLE_COMMON', 'NON_FUNGIBLE_UNIQUE');
CREATE TYPE business_view_type AS ENUM ('PROJECT', 'CREDIT', 'ORGANIZATION', 'METHODOLOGY', 'RETIREMENT');
```

### 6.2 Core Tables

```sql
-- ============================================================
-- BASE MESSAGE TABLE
-- Polymorphic storage for all HCS entity types.
-- The options and documents JSONB fields hold type-specific data.
-- search_vector is auto-populated by trigger.
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
    documents            JSONB,             -- Parsed document content from IPFS
    options              JSONB,             -- Type-specific structured data
    topics               TEXT[],
    tokens               TEXT[],
    last_update          BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
    analytics_update     BIGINT,
    coord_update         BIGINT,

    -- Full-text search vector (auto-populated by trigger)
    search_vector        tsvector,

    created_at           TIMESTAMPTZ DEFAULT NOW(),
    updated_at           TIMESTAMPTZ DEFAULT NOW()
);

-- Core indexes
CREATE INDEX idx_message_topic_id ON message(topic_id);
CREATE INDEX idx_message_type ON message(type);
CREATE INDEX idx_message_status ON message(status);
CREATE INDEX idx_message_last_update ON message(last_update);
CREATE INDEX idx_message_loaded ON message(loaded);
CREATE INDEX idx_message_owner ON message(owner);
CREATE INDEX idx_message_uuid ON message(uuid);
CREATE INDEX idx_message_type_action ON message(type, action);
CREATE INDEX idx_message_type_topic ON message(type, topic_id);

-- Full-text search GIN index
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

-- JSONB indexes for options field queries
CREATE INDEX idx_message_options_did ON message USING GIN((options -> 'did'));
CREATE INDEX idx_message_options_issuer ON message USING GIN((options -> 'issuer'));
CREATE INDEX idx_message_options_owner ON message USING GIN((options -> 'owner'));
CREATE INDEX idx_message_options_relationships ON message USING GIN((options -> 'relationships'));
```

### 6.3 Analytics Tables

```sql
-- ============================================================
-- ENTITY-SPECIFIC ANALYTICS TABLES
-- These replace the embedded analytics object on the message.
-- Populated by the build-business-views maintenance job.
-- ============================================================

-- Policy analytics
CREATE TABLE policy_analytics (
    id                   BIGSERIAL PRIMARY KEY,
    message_id           BIGINT NOT NULL REFERENCES message(id) ON DELETE CASCADE,
    consensus_timestamp  VARCHAR(30) NOT NULL UNIQUE,
    registry_id          VARCHAR(30),
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

-- VC/VP Document analytics
CREATE TABLE document_analytics (
    id                   BIGSERIAL PRIMARY KEY,
    message_id           BIGINT NOT NULL REFERENCES message(id) ON DELETE CASCADE,
    consensus_timestamp  VARCHAR(30) NOT NULL UNIQUE,
    policy_id            VARCHAR(30),
    schema_id            VARCHAR(30),
    schema_name          VARCHAR(500),
    issuer               VARCHAR(200),
    schema_ids           TEXT[],       -- For VPs referencing multiple schemas
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
    child_schemas        JSONB,
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
```

### 6.4 Cache Tables (Worker Writes)

```sql
-- ============================================================
-- CACHE TABLES
-- Written by the worker during Mirror Node sync.
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
```

### 6.5 Operational Tables

```sql
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

-- IPFS file storage (replaces GridFS)
CREATE TABLE ipfs_files (
    id                     BIGSERIAL PRIMARY KEY,
    cid                    VARCHAR(100) NOT NULL UNIQUE,
    content                BYTEA NOT NULL,
    size                   INTEGER,
    content_type           VARCHAR(100),
    created_at             TIMESTAMPTZ DEFAULT NOW()
);

-- Organization prioritization config
CREATE TABLE organization_config (
    id                     BIGSERIAL PRIMARY KEY,
    root_topic_id          VARCHAR(20) NOT NULL,
    topic_id               VARCHAR(20) NOT NULL UNIQUE,
    depth                  INTEGER NOT NULL DEFAULT 0,
    discovered_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_orgconfig_root ON organization_config(root_topic_id);

-- Business domain view (materialized from raw messages)
CREATE TABLE business_view (
    id                     BIGSERIAL PRIMARY KEY,
    type                   business_view_type NOT NULL,
    entity_id              VARCHAR(100) NOT NULL,  -- unique per type
    title                  VARCHAR(500),
    description            TEXT,
    organization_did       VARCHAR(200),
    organization_name      VARCHAR(500),
    policy_topic_id        VARCHAR(20),
    policy_timestamp       VARCHAR(30),
    methodology_name       VARCHAR(500),
    token_id               VARCHAR(20),
    token_symbol           VARCHAR(20),
    total_supply           NUMERIC,
    status                 VARCHAR(50),
    country                VARCHAR(100),
    coordinates            JSONB,            -- { lat, lng }
    schema_context         VARCHAR(500),
    metadata               JSONB,            -- type-specific extra data
    source_timestamps      TEXT[],           -- consensus_timestamps of source messages
    search_vector          tsvector,
    created_at             TIMESTAMPTZ DEFAULT NOW(),
    updated_at             TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(type, entity_id)
);

CREATE INDEX idx_bv_type ON business_view(type);
CREATE INDEX idx_bv_org_did ON business_view(organization_did);
CREATE INDEX idx_bv_policy ON business_view(policy_timestamp);
CREATE INDEX idx_bv_token ON business_view(token_id);
CREATE INDEX idx_bv_search ON business_view USING GIN(search_vector);
CREATE INDEX idx_bv_country ON business_view(country);
CREATE INDEX idx_bv_status ON business_view(status);
```

### 6.6 Materialized Views

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
    COUNT(*) FILTER (WHERE m.type = 'Instance-Policy'
                      AND m.action = 'publish-policy') AS policy_count,
    COUNT(*) FILTER (WHERE m.type = 'Tool'
                      AND m.action = 'publish-tool') AS tool_count,
    COUNT(*) FILTER (WHERE m.type = 'Module'
                      AND m.action = 'publish-module') AS module_count,
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
-- MATERIALIZED VIEW: Landing analytics
-- ============================================================

CREATE MATERIALIZED VIEW mv_landing_analytics AS
SELECT
    date_trunc('day', to_timestamp(m.last_update / 1000.0)) AS date,
    COUNT(*) FILTER (WHERE m.type = 'Standard Registry') AS registries,
    COUNT(*) FILTER (WHERE m.type = 'Instance-Policy'
                      AND m.action = 'publish-policy') AS methodologies,
    COUNT(DISTINCT pc.project_id) AS projects,
    COALESCE(SUM(tc.total_supply) FILTER (
        WHERE tc.type = 'NON_FUNGIBLE_UNIQUE'), 0) AS total_serialized,
    COALESCE(SUM(tc.total_supply) FILTER (
        WHERE tc.type = 'FUNGIBLE_COMMON'), 0) AS total_fungible,
    COALESCE(SUM(tc.total_supply), 0) AS total_issuance
FROM message m
LEFT JOIN project_coordinates pc ON TRUE
LEFT JOIN token_cache tc ON TRUE
WHERE m.type IN ('Standard Registry', 'Instance-Policy')
GROUP BY date_trunc('day', to_timestamp(m.last_update / 1000.0))
ORDER BY date DESC
LIMIT 10;

CREATE UNIQUE INDEX idx_mv_landing_analytics ON mv_landing_analytics(date);
```

### 6.7 Full-Text Search

```sql
-- ============================================================
-- FULL-TEXT SEARCH
-- Replaces the MongoDB $regex on analytics.textSearch
-- ============================================================

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

-- Trigger to auto-update search vector on insert/update
CREATE OR REPLACE FUNCTION update_search_vector() RETURNS trigger AS $$
BEGIN
    NEW.search_vector := build_search_vector(NEW);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trig_message_search_vector
    BEFORE INSERT OR UPDATE ON message
    FOR EACH ROW EXECUTE FUNCTION update_search_vector();

-- Trigger for business_view search vector
CREATE OR REPLACE FUNCTION update_bv_search_vector() RETURNS trigger AS $$
BEGIN
    NEW.search_vector := to_tsvector('simple',
        COALESCE(NEW.title, '') || ' ' ||
        COALESCE(NEW.description, '') || ' ' ||
        COALESCE(NEW.organization_name, '') || ' ' ||
        COALESCE(NEW.methodology_name, '') || ' ' ||
        COALESCE(NEW.country, '') || ' ' ||
        COALESCE(NEW.token_symbol, '') || ' ' ||
        COALESCE(NEW.entity_id, '') || ' ' ||
        COALESCE(NEW.type::text, '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trig_bv_search_vector
    BEFORE INSERT OR UPDATE ON business_view
    FOR EACH ROW EXECUTE FUNCTION update_bv_search_vector();

-- Example search queries:

-- Basic full-text search on messages
SELECT * FROM message
WHERE search_vector @@ plainto_tsquery('simple', 'search term')
ORDER BY ts_rank(search_vector, plainto_tsquery('simple', 'search term')) DESC
LIMIT 10 OFFSET 0;

-- Prefix matching (like current regex behavior)
SELECT * FROM message
WHERE search_vector @@ to_tsquery('simple', 'prefix:*')
ORDER BY ts_rank(search_vector, to_tsquery('simple', 'prefix:*')) DESC;

-- Combined search across messages and business views
SELECT * FROM (
    SELECT 'message' AS source, consensus_timestamp AS id,
           options->>'name' AS name, type::text AS entity_type,
           ts_rank(search_vector, q) AS rank
    FROM message, plainto_tsquery('simple', :search) q
    WHERE search_vector @@ q

    UNION ALL

    SELECT 'business' AS source, entity_id AS id,
           title AS name, type::text AS entity_type,
           ts_rank(search_vector, q) AS rank
    FROM business_view, plainto_tsquery('simple', :search) q
    WHERE search_vector @@ q

    UNION ALL

    SELECT 'token' AS source, token_id AS id,
           name, 'Token' AS entity_type, 1.0 AS rank
    FROM token_cache
    WHERE token_id = :search OR name ILIKE :search || '%'
) results
ORDER BY rank DESC
LIMIT :limit OFFSET :offset;
```

### 6.8 Recursive CTE for Relationships

```sql
-- ============================================================
-- RELATIONSHIP GRAPH TRAVERSAL
-- Replaces the recursive addRelationships() in entities.service.ts
-- Single query instead of N+1 findOne() calls per hop
-- ============================================================

WITH RECURSIVE relationship_graph AS (
    -- Base case: the target message
    SELECT
        m.id, m.consensus_timestamp, m.type, m.action,
        m.options, m.documents, m.owner,
        0 AS depth
    FROM message m
    WHERE m.consensus_timestamp = :target_id

    UNION

    -- Recursive case: follow options.relationships array
    SELECT
        m2.id, m2.consensus_timestamp, m2.type, m2.action,
        m2.options, m2.documents, m2.owner,
        rg.depth + 1
    FROM relationship_graph rg
    CROSS JOIN LATERAL jsonb_array_elements_text(rg.options->'relationships') AS rel_id
    JOIN message m2 ON m2.consensus_timestamp = rel_id
    WHERE rg.depth < 10  -- prevent infinite recursion
)
SELECT DISTINCT ON (consensus_timestamp) *
FROM relationship_graph
ORDER BY consensus_timestamp, depth;
```

---

## 7. Business Data Mapping

### 7.1 Raw Message Type to Business Domain

The core value of Sustainable Explorer is mapping raw blockchain messages to business-domain sustainability entities.

| Raw Message Type | Action | Business Domain | Mapping Logic |
|---|---|---|---|
| `Instance-Policy` | `publish-policy` | **Methodology** | Each published policy represents a carbon methodology |
| `VC-Document` | `create-vc-document` | **Project** | VCs with project-related schema context (identified by schema analysis) |
| `VC-Document` | `create-vc-document` | **Credit** | VCs linked to mint/token-issue events |
| `Standard Registry` | (any) | **Organization** | Each SR is a registered organization |
| `Token` | `create-token` / `mint` | **Credit (issuance)** | Token minting = credit issuance |
| `VC-Document` | `revoke-document` | **Retirement** | Revoked credits = retired credits |
| `VP-Document` | `create-vp-document` | **Credit (verification)** | VP wrapping credit VCs = verified credits |

### 7.2 Business View Schemas by Type

#### PROJECT
```typescript
interface ProjectView {
  type: 'PROJECT';
  entity_id: string;              // Derived from VC credentialSubject.id or consensus_timestamp
  title: string;                  // From VC credentialSubject (project name field)
  description: string;            // From VC credentialSubject
  organization_did: string;       // Issuer DID
  organization_name: string;      // Resolved from registry
  policy_topic_id: string;        // Topic where this project was registered
  policy_timestamp: string;       // Which policy/methodology this project uses
  methodology_name: string;       // Resolved policy name
  status: string;                 // 'active' | 'inactive'
  country: string;                // Extracted from VC credentialSubject
  coordinates: {                  // From project_coordinates table
    lat: number;
    lng: number;
  };
  metadata: {
    projectType: string;          // e.g. "Renewable Energy", "Forestry"
    startDate: string;
    credentialSubject: object;    // Full VC subject for detail view
    relatedCredits: string[];     // Token IDs of issued credits
  };
  source_timestamps: string[];    // All consensus_timestamps contributing to this view
}
```

#### CREDIT
```typescript
interface CreditView {
  type: 'CREDIT';
  entity_id: string;              // token_id
  title: string;                  // Token name
  token_id: string;               // Hedera token ID
  token_symbol: string;           // Token symbol
  total_supply: number;           // Current supply from token_cache
  organization_did: string;       // Treasury account owner's DID
  organization_name: string;      // Resolved
  policy_timestamp: string;       // Policy that created this token
  methodology_name: string;       // Resolved
  metadata: {
    tokenType: 'FUNGIBLE_COMMON' | 'NON_FUNGIBLE_UNIQUE';
    treasury: string;             // Hedera account
    decimals: number;
    mintEvents: Array<{
      timestamp: string;
      amount: number;
    }>;
    linkedProjects: string[];     // Project entity_ids
  };
  source_timestamps: string[];
}
```

#### ORGANIZATION
```typescript
interface OrganizationView {
  type: 'ORGANIZATION';
  entity_id: string;              // DID
  title: string;                  // Organization name from options.attributes
  organization_did: string;       // Same as entity_id
  organization_name: string;      // Same as title
  metadata: {
    hederaAccountId: string;      // owner field
    registrantTopicId: string;
    policyCount: number;          // From mv_registry_activity
    vcCount: number;
    tokenCount: number;
    projectCount: number;         // From business_view count
    totalIssuance: number;        // Sum of all credit supplies
  };
  source_timestamps: string[];
}
```

#### METHODOLOGY
```typescript
interface MethodologyView {
  type: 'METHODOLOGY';
  entity_id: string;              // Policy consensus_timestamp
  title: string;                  // Policy name from options.name
  description: string;            // From options.description
  organization_did: string;       // Policy owner DID
  organization_name: string;      // Resolved
  policy_timestamp: string;       // Same as entity_id
  metadata: {
    instanceTopicId: string;
    version: string;
    tools: string[];
    schemaCount: number;          // From mv_policy_activity
    vcCount: number;
    projectCount: number;         // From business_view count
    totalIssuance: number;
  };
  source_timestamps: string[];
}
```

---

## 8. Caching Strategy (Redict)

### 8.1 Cache Architecture

Redict serves three purposes:
1. **BullMQ backend** -- job queue persistence (managed by BullMQ, uses `bull:` key prefix)
2. **Response cache** -- cached API responses for frequently accessed data
3. **Pub/Sub** -- event notification for SSE and cache invalidation

### 8.2 Cache Keys and TTLs

| Cache Key Pattern | TTL | Description |
|---|---|---|
| `explorer:dashboard` | 30s | Dashboard aggregated stats |
| `explorer:projects:list:{page}:{pageSize}:{sort}:{filters_hash}` | 60s | Project list pages |
| `explorer:projects:{id}` | 120s | Individual project detail |
| `explorer:credits:list:{page}:{pageSize}:{sort}:{filters_hash}` | 60s | Credit list pages |
| `explorer:credits:{tokenId}` | 120s | Individual credit detail |
| `explorer:methodologies:list:{page}:{pageSize}` | 120s | Methodology list |
| `explorer:methodologies:{id}` | 120s | Methodology detail |
| `explorer:organizations:list:{page}:{pageSize}` | 120s | Organization list |
| `explorer:organizations:{did}` | 120s | Organization detail |
| `explorer:search:{query_hash}` | 30s | Search results |
| `explorer:sync-status` | 10s | Sync pipeline status |
| `explorer:analytics:{type}:{range}` | 300s | Analytics data |

### 8.3 Cache Invalidation Strategy

**Event-driven invalidation:**
1. When `maintenance/build-business-views` completes, it publishes to Redict Pub/Sub channel `explorer:invalidate`
2. The API server subscribes to this channel
3. On receiving invalidation event, the API server deletes affected cache keys by pattern

```typescript
// Worker publishes after business view rebuild
await redictClient.publish('explorer:invalidate', JSON.stringify({
  type: 'business-view-updated',
  affectedTypes: ['PROJECT', 'CREDIT'],
  timestamp: Date.now(),
}));

// API server subscribes
subscriber.subscribe('explorer:invalidate', (message) => {
  const event = JSON.parse(message);
  // Delete matching cache keys
  await invalidateByPattern(`explorer:projects:*`);
  await invalidateByPattern(`explorer:credits:*`);
  await invalidateByPattern(`explorer:dashboard`);
});
```

**Pattern-based deletion:**
```typescript
async function invalidateByPattern(pattern: string): Promise<void> {
  let cursor = '0';
  do {
    const [nextCursor, keys] = await redictClient.scan(
      cursor, 'MATCH', pattern, 'COUNT', 100
    );
    cursor = nextCursor;
    if (keys.length > 0) {
      await redictClient.del(...keys);
    }
  } while (cursor !== '0');
}
```

### 8.4 Cache-Aside Pattern

All API endpoints follow the cache-aside pattern:

```typescript
async getDashboard(): Promise<DashboardResponse> {
  const cacheKey = 'explorer:dashboard';
  const cached = await this.redict.get(cacheKey);
  if (cached) return JSON.parse(cached);

  const data = await this.buildDashboardFromDb();
  await this.redict.setex(cacheKey, 30, JSON.stringify(data));
  return data;
}
```

---

## 9. API Design

The API serves two audiences:

1. **Internal** — the Sustainable Explorer frontend (Nuxt 3 app)
2. **Public** — third-party developers consuming the API programmatically

All endpoints are versioned under `/api/v1/`. The API server is a NestJS application with OpenAPI/Swagger documentation auto-generated from decorators.

### 9.0 Public API Layer

#### Authentication

Public API consumers authenticate via API keys. The Explorer frontend uses a separate internal path (no API key required when served from the same origin).

```
External consumer:  GET /api/v1/projects?apiKey=sk_live_abc123
                    or
                    GET /api/v1/projects  (Header: X-API-Key: sk_live_abc123)

Internal frontend:  GET /api/v1/projects  (same-origin, no key needed)
```

#### API Key Management

API keys are stored in PostgreSQL:

```sql
CREATE TABLE api_keys (
    id              BIGSERIAL PRIMARY KEY,
    key_hash        VARCHAR(64) NOT NULL UNIQUE,  -- SHA-256 of the key
    key_prefix      VARCHAR(12) NOT NULL,          -- "sk_live_abc" for display
    name            VARCHAR(200) NOT NULL,          -- "Acme Corp Production"
    owner_email     VARCHAR(200),
    permissions     TEXT[] DEFAULT '{read}',         -- 'read', 'search', 'analytics'
    rate_limit      INTEGER DEFAULT 100,            -- requests per minute
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ                     -- NULL = never expires
);
```

#### Rate Limiting

Per API key, tracked in Redict:

```
Key:    se:ratelimit:{keyPrefix}:{minute}
Value:  counter (INCR)
TTL:    120 seconds

Default: 100 requests/minute (configurable per key)
Exceeded: HTTP 429 with Retry-After header
```

Internal frontend requests (same-origin, no API key) are rate-limited by IP at a higher threshold (1000 req/min).

#### OpenAPI / Swagger

Auto-generated from NestJS decorators, available at:

```
GET /api/docs        → Swagger UI
GET /api/docs-json   → OpenAPI 3.0 JSON spec
GET /api/docs-yaml   → OpenAPI 3.0 YAML spec
```

#### Response Format

All responses follow a consistent envelope:

```json
{
  "data": { ... },           // or [...] for lists
  "meta": {
    "page": 1,
    "limit": 20,
    "total": 1203,
    "hasMore": true,
    "cursor": "eyJ0..."     // for cursor-based pagination
  },
  "syncStatus": {
    "lastSync": "2026-03-20T10:30:00Z",
    "dataSource": "both"    // "mirror_node", "guardian_api", or "both"
  }
}
```

#### CORS

```typescript
// Configurable via environment
API_CORS_ORIGINS=https://explorer.example.com,https://app.example.com
```

#### Versioning

All public endpoints are under `/api/v1/`. Future breaking changes go to `/api/v2/` while `/api/v1/` remains stable.

### 9.1 Dashboard

#### `GET /api/v1/dashboard`

Returns aggregated statistics for the landing page.

**Response:**
```json
{
  "registries": 42,
  "methodologies": 156,
  "projects": 1203,
  "totalIssuance": "1500000000",
  "totalSerialized": "850000",
  "totalFungible": "1499150000",
  "recentActivity": [
    {
      "date": "2026-03-20",
      "registries": 42,
      "methodologies": 156,
      "projects": 1203,
      "totalIssuance": "1500000000"
    }
  ],
  "topOrganizations": [
    {
      "did": "did:hedera:mainnet:...",
      "name": "Verra",
      "policyCount": 12,
      "projectCount": 340
    }
  ],
  "syncStatus": {
    "lastSync": "2026-03-20T10:30:00Z",
    "topicsIndexed": 1500,
    "messagesProcessed": 523000,
    "pendingJobs": 12
  }
}
```

### 9.2 Projects

#### `GET /api/v1/projects`

**Query Parameters:**

| Param | Type | Default | Description |
|---|---|---|---|
| `page` | number | 1 | Page number |
| `pageSize` | number | 20 | Items per page (max 100) |
| `sort` | string | `-created_at` | Sort field (prefix `-` for DESC) |
| `search` | string | | Full-text search |
| `organization` | string | | Filter by organization DID |
| `methodology` | string | | Filter by methodology ID |
| `country` | string | | Filter by country |
| `status` | string | | Filter by status |

**Response:**
```json
{
  "items": [
    {
      "id": "project-abc-123",
      "title": "Solar Farm Delta",
      "organization": {
        "did": "did:hedera:mainnet:...",
        "name": "Green Energy Corp"
      },
      "methodology": {
        "id": "1680000000.000000000",
        "name": "GS Methodology: Renewable Energy v1.0"
      },
      "country": "Kenya",
      "status": "active",
      "totalCredits": "50000",
      "createdAt": "2026-01-15T08:00:00Z"
    }
  ],
  "total": 1203,
  "page": 1,
  "pageSize": 20,
  "pageCount": 61
}
```

#### `GET /api/v1/projects/:id`

**Response:**
```json
{
  "id": "project-abc-123",
  "title": "Solar Farm Delta",
  "description": "100MW solar installation in Nairobi...",
  "organization": {
    "did": "did:hedera:mainnet:...",
    "name": "Green Energy Corp",
    "hederaAccountId": "0.0.12345"
  },
  "methodology": {
    "id": "1680000000.000000000",
    "name": "GS Methodology: Renewable Energy v1.0",
    "description": "..."
  },
  "country": "Kenya",
  "coordinates": { "lat": -1.286389, "lng": 36.817223 },
  "status": "active",
  "credits": [
    {
      "tokenId": "0.0.98765",
      "symbol": "SREC",
      "totalSupply": "50000",
      "type": "FUNGIBLE_COMMON"
    }
  ],
  "documents": [
    {
      "type": "VC-Document",
      "consensusTimestamp": "1680000100.000000000",
      "issuer": "did:hedera:mainnet:...",
      "schemaName": "Project Registration"
    }
  ],
  "timeline": [
    {
      "timestamp": "1680000100.000000000",
      "event": "Project Registered",
      "type": "VC-Document"
    },
    {
      "timestamp": "1680000200.000000000",
      "event": "Credits Issued",
      "type": "Token"
    }
  ],
  "sourceTimestamps": ["1680000100.000000000", "1680000200.000000000"]
}
```

### 9.3 Credits

#### `GET /api/v1/credits`

**Query Parameters:** `page`, `pageSize`, `sort`, `search`, `organization`, `methodology`, `tokenType`

**Response:** Same pagination structure as projects, with credit-specific items.

#### `GET /api/v1/credits/:tokenId`

**Response:**
```json
{
  "tokenId": "0.0.98765",
  "name": "Solar Renewable Energy Credits",
  "symbol": "SREC",
  "type": "FUNGIBLE_COMMON",
  "totalSupply": "50000",
  "decimals": 2,
  "treasury": "0.0.12345",
  "organization": {
    "did": "did:hedera:mainnet:...",
    "name": "Green Energy Corp"
  },
  "methodology": {
    "id": "1680000000.000000000",
    "name": "GS Methodology: Renewable Energy v1.0"
  },
  "linkedProjects": [
    { "id": "project-abc-123", "title": "Solar Farm Delta" }
  ],
  "mintHistory": [
    {
      "timestamp": "1680000200.000000000",
      "amount": "25000",
      "serialRange": null
    },
    {
      "timestamp": "1680000300.000000000",
      "amount": "25000",
      "serialRange": null
    }
  ],
  "nfts": null
}
```

### 9.4 Methodologies

#### `GET /api/v1/methodologies`

**Query Parameters:** `page`, `pageSize`, `sort`, `search`, `organization`

#### `GET /api/v1/methodologies/:id`

**Response:**
```json
{
  "id": "1680000000.000000000",
  "name": "GS Methodology: Renewable Energy v1.0",
  "description": "Gold Standard methodology for...",
  "organization": {
    "did": "did:hedera:mainnet:...",
    "name": "Gold Standard"
  },
  "instanceTopicId": "0.0.5678",
  "version": "1.0",
  "stats": {
    "schemaCount": 8,
    "vcCount": 1500,
    "vpCount": 300,
    "projectCount": 45,
    "totalIssuance": "500000"
  },
  "schemas": [
    { "name": "Project Registration", "consensusTimestamp": "..." },
    { "name": "Monitoring Report", "consensusTimestamp": "..." }
  ],
  "tools": ["0.0.111", "0.0.222"],
  "derivations": [
    { "id": "1690000000.000000000", "name": "Derived Methodology v1.1" }
  ]
}
```

### 9.5 Organizations

#### `GET /api/v1/organizations`

**Query Parameters:** `page`, `pageSize`, `sort`, `search`

#### `GET /api/v1/organizations/:did`

**Response:**
```json
{
  "did": "did:hedera:mainnet:...",
  "name": "Green Energy Corp",
  "hederaAccountId": "0.0.12345",
  "registrantTopicId": "0.0.5000",
  "stats": {
    "policyCount": 5,
    "projectCount": 45,
    "vcCount": 3000,
    "vpCount": 500,
    "tokenCount": 8,
    "userCount": 12,
    "totalIssuance": "750000"
  },
  "methodologies": [
    { "id": "...", "name": "GS Methodology: Renewable Energy v1.0" }
  ],
  "recentProjects": [
    { "id": "project-abc-123", "title": "Solar Farm Delta" }
  ]
}
```

### 9.6 Analytics

#### `GET /api/v1/analytics/overview`

Returns time-series data for charts.

**Query Parameters:** `range` (7d, 30d, 90d, 1y, all), `granularity` (day, week, month)

**Response:**
```json
{
  "range": "30d",
  "granularity": "day",
  "series": [
    {
      "date": "2026-02-18",
      "registries": 40,
      "methodologies": 150,
      "projects": 1150,
      "issuance": "1400000000"
    }
  ]
}
```

#### `GET /api/v1/analytics/issuance`

Token issuance analytics.

#### `GET /api/v1/analytics/geography`

Project distribution by country/coordinates.

### 9.7 Search

#### `GET /api/v1/search`

Unified search across all business entities and raw messages.

**Query Parameters:**

| Param | Type | Description |
|---|---|---|
| `q` | string | Search query (required) |
| `type` | string | Filter by entity type (project, credit, methodology, organization, message) |
| `page` | number | Page number |
| `pageSize` | number | Items per page |

**Response:**
```json
{
  "items": [
    {
      "source": "business",
      "type": "PROJECT",
      "id": "project-abc-123",
      "title": "Solar Farm Delta",
      "description": "100MW solar installation...",
      "rank": 0.95
    },
    {
      "source": "message",
      "type": "VC-Document",
      "id": "1680000100.000000000",
      "title": null,
      "description": null,
      "rank": 0.72
    }
  ],
  "total": 15,
  "page": 1,
  "pageSize": 20
}
```

### 9.8 Sync Status

#### `GET /api/v1/sync-status`

**Response:**
```json
{
  "status": "syncing",
  "topics": {
    "total": 1500,
    "synced": 1488,
    "pending": 12
  },
  "messages": {
    "total": 523000,
    "processed": 522800,
    "pending": 200
  },
  "ipfsFiles": {
    "total": 45000,
    "fetched": 44900,
    "pending": 100,
    "failed": 15
  },
  "queues": {
    "mirror-node-topics": { "active": 3, "waiting": 9, "completed": 15000, "failed": 2 },
    "mirror-node-messages": { "active": 8, "waiting": 200, "completed": 522800, "failed": 10 },
    "mirror-node-tokens": { "active": 1, "waiting": 0, "completed": 2000, "failed": 0 },
    "ipfs-files": { "active": 3, "waiting": 97, "completed": 44900, "failed": 15 }
  },
  "lastMaterializedViewRefresh": "2026-03-20T10:29:30Z",
  "lastBusinessViewBuild": "2026-03-20T10:28:00Z",
  "uptime": "3d 14h 22m"
}
```

### 9.9 SSE Events

#### `GET /api/v1/events`

Server-Sent Events stream for real-time updates.

**Event types:**

| Event | Payload | When |
|---|---|---|
| `sync-progress` | `{ topicsProcessed, messagesProcessed }` | Every 5s during active sync |
| `new-project` | `{ id, title, organization }` | New project business view created |
| `new-credit-issuance` | `{ tokenId, amount }` | New credit minting detected |
| `business-views-updated` | `{ types, count }` | After business view rebuild |
| `materialized-views-refreshed` | `{ timestamp }` | After MV refresh |

**Implementation:**
```typescript
@Sse('events')
events(): Observable<MessageEvent> {
  return new Observable((subscriber) => {
    const redisSubscriber = this.redict.duplicate();
    redisSubscriber.subscribe('explorer:events');
    redisSubscriber.on('message', (channel, message) => {
      const event = JSON.parse(message);
      subscriber.next({ data: event, type: event.type });
    });
    return () => redisSubscriber.unsubscribe('explorer:events');
  });
}
```

---

## 10. Frontend Architecture

**Stack:** Vue 3 + Nuxt 3 + TanStack Query + TanStack Table

**Why this stack:**
- **Nuxt 3** — SSR built-in (critical for a public explorer — SEO, shareability), file-based routing, `useAsyncData` with SSR hydration, route-based code splitting
- **TanStack Query** — handles data fetching, caching, deduplication, background refresh, stale-while-revalidate. Replaces manual HTTP services and most client-side caching
- **TanStack Table** — headless, type-safe data tables with sorting, filtering, pagination
- **Vue 3 Composition API** — simpler mental model, smaller bundle (~50KB vs Angular's ~150KB)

### 10.1 Route Structure (Nuxt file-based routing)

```
pages/
  index.vue                        → / (Dashboard)
  projects/
    index.vue                      → /projects (list)
    [id].vue                       → /projects/:id (detail)
  credits/
    index.vue                      → /credits (list)
    [tokenId].vue                  → /credits/:tokenId (detail)
  methodologies/
    index.vue                      → /methodologies (list)
    [id].vue                       → /methodologies/:id (detail)
  organizations/
    index.vue                      → /organizations (list)
    [did].vue                      → /organizations/:did (detail)
  analytics/
    index.vue                      → /analytics (overview)
    issuance.vue                   → /analytics/issuance
    geography.vue                  → /analytics/geography (map)
  search.vue                       → /search (results)
  status.vue                       → /status (sync dashboard)
```

### 10.2 Component Structure

```
components/
  layout/
    AppHeader.vue                  -- Navigation bar with search
    AppFooter.vue                  -- Footer with sync status indicator
    AppSidebar.vue                 -- Navigation sidebar
  shared/
    DataTable.vue                  -- TanStack Table wrapper (sortable, filterable, paginated)
    SearchBar.vue                  -- Global search input with debounce
    StatCard.vue                   -- Dashboard statistic card
    SkeletonLoader.vue             -- Generic skeleton placeholder
    EntityBadge.vue                -- Type badge (Project, Credit, etc.)
    CursorPagination.vue           -- Cursor-based page controls
    ChartWrapper.vue               -- Chart.js or ECharts wrapper
    SyncStatusBanner.vue           -- Top banner showing sync progress
  projects/
    ProjectListFilters.vue         -- Filter sidebar for project list
    ProjectTimeline.vue            -- Project activity timeline
    ProjectCreditSummary.vue       -- Credits issued under project
  credits/
    CreditMintHistory.vue          -- Token mint/transfer history
    CreditTokenInfo.vue            -- Token metadata display
  analytics/
    TimeSeriesChart.vue            -- Issuance over time
    GeographyMap.vue               -- Map with project pins (Mapbox GL or Leaflet)
    BreakdownChart.vue             -- Pie/bar chart for credit breakdown
```

### 10.3 TanStack Query — Data Fetching & Caching

TanStack Query replaces manual HTTP services, client-side caching, and most RxJS state management.

```typescript
// composables/useProjects.ts
export function useProjects(filters: Ref<ProjectFilters>) {
  return useQuery({
    queryKey: ['projects', filters],
    queryFn: () => $fetch('/api/v1/projects', { params: filters.value }),
    staleTime: 30_000,         // serve cached for 30 seconds
    refetchInterval: 60_000,   // background refresh every 60 seconds
    placeholderData: keepPreviousData,  // show old data while fetching new page
  })
}

// composables/useProjectDetail.ts
export function useProjectDetail(id: Ref<string>) {
  return useQuery({
    queryKey: ['project', id],
    queryFn: () => $fetch(`/api/v1/projects/${id.value}`),
    staleTime: 60_000,
  })
}

// composables/useDashboard.ts
export function useDashboard() {
  return useQuery({
    queryKey: ['dashboard'],
    queryFn: () => $fetch('/api/v1/dashboard'),
    staleTime: 10_000,         // dashboard refreshes frequently
    refetchInterval: 30_000,
  })
}

// composables/useSearch.ts
export function useSearch(query: Ref<string>) {
  return useQuery({
    queryKey: ['search', query],
    queryFn: () => $fetch('/api/v1/search', { params: { q: query.value } }),
    enabled: computed(() => query.value.length >= 2),  // only search after 2 chars
    staleTime: 60_000,
  })
}
```

**What TanStack Query handles automatically:**
- **Deduplication** — 10 components requesting `['dashboard']` = 1 API call
- **Background refetch** — data auto-refreshes while showing stale data
- **Cache invalidation** — via SSE events (see 10.5)
- **Loading/error states** — `isLoading`, `isFetching`, `isError`, `error` refs
- **Pagination** — `keepPreviousData` shows old page while loading next

### 10.4 TanStack Table — Data Tables

```vue
<!-- components/shared/DataTable.vue -->
<script setup lang="ts" generic="T">
import { useVueTable, getCoreRowModel, getSortedRowModel } from '@tanstack/vue-table'

const props = defineProps<{
  data: T[]
  columns: ColumnDef<T>[]
  isLoading: boolean
}>()

const table = useVueTable({
  get data() { return props.data },
  columns: props.columns,
  getCoreRowModel: getCoreRowModel(),
  getSortedRowModel: getSortedRowModel(),
})
</script>
```

Usage in pages:

```vue
<!-- pages/projects/index.vue -->
<script setup>
const filters = ref({ page: 1, methodology: '', org: '' })
const { data, isLoading, isFetching } = useProjects(filters)

const columns = [
  { accessorKey: 'displayName', header: 'Project' },
  { accessorKey: 'methodology', header: 'Methodology' },
  { accessorKey: 'organization', header: 'Organization' },
  { accessorKey: 'creditsIssued', header: 'Credits Issued', cell: formatNumber },
  { accessorKey: 'status', header: 'Status', cell: StatusBadge },
]
</script>

<template>
  <DataTable :data="data?.data ?? []" :columns="columns" :is-loading="isLoading" />
  <CursorPagination :meta="data?.meta" @next="filters.cursor = data?.meta.cursor" />
  <div v-if="isFetching" class="subtle-loading-indicator" />
</template>
```

### 10.5 SSE Integration with TanStack Query

SSE events trigger TanStack Query cache invalidation — no manual refetching needed.

```typescript
// composables/useExplorerSSE.ts
export function useExplorerSSE() {
  const queryClient = useQueryClient()
  const { status, data } = useEventSource('/api/v1/events')

  watch(data, (raw) => {
    if (!raw) return
    const event = JSON.parse(raw)

    switch (event.type) {
      case 'sync-progress':
        queryClient.invalidateQueries({ queryKey: ['sync-status'] })
        break
      case 'new-project':
        queryClient.invalidateQueries({ queryKey: ['projects'] })
        queryClient.invalidateQueries({ queryKey: ['dashboard'] })
        break
      case 'new-credit-issuance':
        queryClient.invalidateQueries({ queryKey: ['credits'] })
        queryClient.invalidateQueries({ queryKey: ['dashboard'] })
        break
      case 'business-views-updated':
        queryClient.invalidateQueries() // invalidate everything
        break
      case 'materialized-views-refreshed':
        queryClient.invalidateQueries({ queryKey: ['dashboard'] })
        queryClient.invalidateQueries({ queryKey: ['analytics'] })
        break
    }
  })
}

// app.vue — activate SSE globally
// <script setup>
// useExplorerSSE()
// </script>
```

### 10.6 Data Loading Strategy

TanStack Query handles the three-tier loading pattern automatically:

```
1. SKELETON  → isLoading = true (first load, no cache)
              Show <SkeletonLoader /> placeholder

2. CACHED    → isLoading = false, isFetching = false
              TanStack serves from in-memory cache (staleTime not exceeded)

3. STALE     → isLoading = false, isFetching = true
              Show cached data + subtle refresh indicator
              TanStack refetches in background, swaps data when ready

4. SSE EVENT → queryClient.invalidateQueries()
              TanStack refetches immediately, swaps when ready
```

No manual cache service needed. TanStack Query IS the cache layer for the frontend.

### 10.7 Nuxt SSR Considerations

```typescript
// pages/projects/[id].vue — SSR-friendly data fetching
<script setup>
const route = useRoute()
const { data, pending } = await useAsyncData(
  `project-${route.params.id}`,
  () => $fetch(`/api/v1/projects/${route.params.id}`)
)
// SSR: rendered on server, hydrated on client
// Client nav: fetched client-side with TanStack Query
</script>
```

For pages that need SEO (dashboard, project list), use `useAsyncData` for SSR. For interactive pages (search, analytics), use TanStack Query client-side only.

### 10.8 Impact on Redict Caching

With TanStack Query on the frontend:

| Cache | Still need Redict? | Why |
|-------|-------------------|-----|
| Dashboard aggregates | **Yes** | Public API consumers don't have TanStack |
| Entity lists | **Yes** | Public API consumers |
| Entity details | **Reduce TTL** | TanStack handles frontend; keep short TTL for API consumers |
| Sync status | **No** | Cheap query, TanStack polls + SSE invalidates |
| Search results | **Yes** | Expensive tsvector queries worth caching for all consumers |

---

## 11. Code Reuse Plan

### 11.1 COPY (use directly or with minimal modification)

These files can be copied into the new codebase with minor adaptations (remove MongoDB/NATS imports, adjust TypeScript paths).

| Source File | What to Copy | Modifications Needed |
|---|---|---|
| `indexer-interfaces/src/types/message-type.type.ts` | MessageType enum (all 30+ values) | None |
| `indexer-interfaces/src/types/message-action.type.ts` | MessageAction enum | None |
| `indexer-interfaces/src/types/token.type.ts` | TokenType enum | None |
| `indexer-interfaces/src/types/priority-status.type.ts` | PriorityStatus enum | None |
| `indexer-interfaces/src/types/message-status.type.ts` | MessageStatus enum | None |
| `indexer-interfaces/src/interfaces/message.interface.ts` | IMessage interface | None |
| `indexer-interfaces/src/interfaces/raw-message.interface.ts` | IRawMessage interface | None |
| `indexer-interfaces/src/interfaces/raw-token.interface.ts` | IRawToken interface | None |
| `indexer-interfaces/src/interfaces/raw-topic.interface.ts` | IRawTopic interface | None |
| `indexer-interfaces/src/interfaces/raw-nft.interface.ts` | IRawNft interface | None |
| `indexer-interfaces/src/interfaces/relationships.interface.ts` | Relationship types | None |
| `indexer-interfaces/src/interfaces/schema/*` | Schema parsing types | None |
| `indexer-interfaces/src/constants/ipfs-cid-patters.const.ts` | IPFS CID regex patterns | None |
| `indexer-interfaces/src/helpers/schema-helper.ts` | Schema parsing utilities | None |
| `indexer-interfaces/src/validators/**/*.ts` | Label/rule/formula validators | None |
| `indexer-worker-service/src/loaders/hedera-service.ts` | Mirror Node HTTP client | Remove NATS imports; use injectable NestJS service pattern |
| `indexer-worker-service/src/utils/parser.ts` | HCS message parser (base64 decode, JSON parse, type classification) | None |
| `indexer-worker-service/src/loaders/ipfs-service.ts` | IPFS gateway client | Remove GridFS storage; return raw content instead |
| `indexer-worker-service/src/loaders/ipfs/ipfs-node.ts` | IPFS node utilities | None |

### 11.2 STUDY AND PORT (understand logic, rewrite for PostgreSQL)

These files contain business logic that must be understood and re-implemented using SQL or the new architecture.

| Source File | Logic to Port | New Implementation |
|---|---|---|
| `indexer-service/src/helpers/synchronizers/synchronize-policy.ts` | Policy enrichment: link to SR, extract tools/tokens from ZIP, compute hash | SQL INSERT INTO policy_analytics SELECT ... JOIN |
| `indexer-service/src/helpers/synchronizers/synchronize-vcs.ts` | VC-to-policy linking, schema extraction | SQL in build-business-views job |
| `indexer-service/src/helpers/synchronizers/synchronize-vp.ts` | VP-to-policy linking | SQL in build-business-views job |
| `indexer-service/src/helpers/synchronizers/synchronize-schema.ts` | Schema metadata extraction | SQL + IPFS JSON parsing |
| `indexer-service/src/helpers/synchronizers/synchronize-registry.ts` | Registry enrichment | SQL in registry_analytics population |
| `indexer-service/src/helpers/synchronizers/synchronize-analytics.ts` | Daily aggregate computation | Materialized views (mv_landing_analytics) |
| `indexer-service/src/helpers/synchronizers/synchronize-projects.ts` | Geo coordinate extraction from VCs | build-business-views job + project_coordinates |
| `indexer-service/src/helpers/synchronizers/synchronize-topic.ts` | Topic relationship discovery | Recursive CTE + organization_config |
| `indexer-service/src/helpers/synchronizers/synchronize-role.ts` | Role document enrichment | SQL join |
| `indexer-service/src/helpers/synchronizers/synchronize-dids.ts` | DID enrichment | SQL join |
| `indexer-service/src/helpers/synchronizers/synchronize-module.ts` | Module enrichment | SQL join |
| `indexer-service/src/helpers/synchronizers/synchronize-tool.ts` | Tool enrichment | SQL join |
| `indexer-service/src/helpers/synchronizers/synchronize-contracts.ts` | Contract enrichment | SQL join |
| `indexer-service/src/helpers/synchronizers/synchronize-labels.ts` | Label enrichment | SQL join |
| `indexer-service/src/helpers/synchronizers/synchronize-formula.ts` | Formula enrichment | SQL join |
| `indexer-service/src/helpers/synchronizers/synchronize-schema-package.ts` | Schema package processing | SQL join |
| `indexer-service/src/utils/relationships.ts` | Recursive relationship graph traversal | Recursive CTE (see section 6.8) |
| `indexer-service/src/helpers/text-search-options.ts` | textSearch string concatenation logic | tsvector trigger function (see section 6.7) |
| `indexer-service/src/api/entities.service.ts` | All entity query patterns (N+1 counts, filtering, pagination) | Materialized views + TypeORM query builder |
| `indexer-service/src/api/search.service.ts` | Full-text search with $regex | tsvector @@ plainto_tsquery |
| `indexer-service/src/api/landing.service.ts` | Landing page analytics queries | SELECT from mv_landing_analytics |

### 11.3 REWRITE (new implementation, no direct correspondence)

| Component | Why Rewrite |
|---|---|
| Database layer (entities, repositories, migrations) | PostgreSQL with TypeORM instead of MongoDB with MikroORM |
| Job queue system | BullMQ instead of custom Job/Jobs polling loop |
| API layer (controllers, DTOs) | New REST endpoints for Sustainable Explorer (not NATS proxying) |
| Inter-service communication | BullMQ + Redict Pub/Sub instead of NATS |
| Caching layer | Redict cache-aside pattern (not present in current indexer) |
| SSE event system | New (not present in current indexer) |
| Business data mapping | New (maps raw messages to sustainability domain) |
| Frontend | New Nuxt 3 app with Vue 3, TanStack Query/Table, SSR |
| Docker setup | New docker-compose with PostgreSQL + Redict |
| Configuration | New env vars, no NATS/MongoDB config |

---

## 12. Configuration

### 12.1 Environment Variables

```bash
# ============================================================
# NETWORK CONFIGURATION
# ============================================================

# Hedera network: mainnet, testnet, previewnet
HEDERA_NET=mainnet

# Mirror Node base URL (auto-resolved from HEDERA_NET if not set)
# Default for mainnet: https://mainnet.mirrornode.hedera.com
# Default for testnet: https://testnet.mirrornode.hedera.com
HEDERA_MIRROR_NODE_URL=https://mainnet.mirrornode.hedera.com

# IPFS gateway URLs (comma-separated, tried in order)
IPFS_GATEWAYS=https://ipfs.io/ipfs/,https://cloudflare-ipfs.com/ipfs/,https://gateway.pinata.cloud/ipfs/

# ============================================================
# DATABASE (PostgreSQL)
# ============================================================

DB_HOST=localhost
DB_PORT=5432
DB_DATABASE=sustainable_explorer
DB_USER=explorer
DB_PASSWORD=explorer_password

# Connection pool
DB_POOL_MIN=2
DB_POOL_MAX=10

# ============================================================
# CACHE / QUEUE (Redict)
# ============================================================

REDICT_HOST=localhost
REDICT_PORT=6379
REDICT_PASSWORD=
REDICT_DB=0

# ============================================================
# ORGANIZATION PRIORITIZATION
# ============================================================

# Root topic ID for the prioritized organization.
# All topics discovered under this root get BullMQ priority 1.
# Leave empty for no prioritization (all topics equal priority).
ORG_ROOT_TOPIC_ID=

# ============================================================
# WORKER CONFIGURATION
# ============================================================

# Job concurrency per queue
WORKER_TOPIC_CONCURRENCY=5
WORKER_MESSAGE_CONCURRENCY=10
WORKER_TOKEN_CONCURRENCY=2
WORKER_IPFS_CONCURRENCY=3

# Materialized view refresh interval (seconds)
MV_REFRESH_INTERVAL=60

# Mirror Node polling delay between batches (milliseconds)
MIRROR_NODE_POLL_DELAY=1000

# IPFS fetch timeout (milliseconds)
IPFS_FETCH_TIMEOUT=180000

# ============================================================
# GUARDIAN API INTEGRATION (Optional — co-located mode)
# ============================================================

# Guardian API base URL. Leave empty to run in standalone mode (Mirror Node only).
GUARDIAN_API_URL=

# Dedicated read-only user credentials for Guardian API access.
# Required only when GUARDIAN_API_URL is set.
GUARDIAN_API_USERNAME=sustainable-explorer
GUARDIAN_API_PASSWORD=

# Guardian API polling intervals (seconds)
GUARDIAN_API_POLICY_INTERVAL=30
GUARDIAN_API_SCHEMA_INTERVAL=60
GUARDIAN_API_TOKEN_INTERVAL=60
GUARDIAN_API_MODULE_INTERVAL=120
GUARDIAN_API_TOOL_INTERVAL=120

# ============================================================
# REDICT SHARING (Co-located mode)
# ============================================================

# When sharing Redict with Guardian cluster, use a separate DB number
# and key prefix to avoid collisions.
REDICT_DB=0                   # Use 1+ when sharing with Guardian (Guardian uses 0)
REDICT_KEY_PREFIX=se:         # Namespace prefix for all keys

# ============================================================
# API SERVER
# ============================================================

API_PORT=3030
API_CORS_ORIGIN=http://localhost:4200

# ============================================================
# LOGGING
# ============================================================

LOG_LEVEL=info
# Options: error, warn, info, debug, verbose

# ============================================================
# ENVIRONMENT PREFIX
# ============================================================

# Optional prefix for database name: {ENV}_{NET}_{DB}
GUARDIAN_ENV=
```

### 12.2 Default Mirror Node Resolution

```typescript
function getDefaultMirrorNodeUrl(network: string): string {
  switch (network) {
    case 'mainnet':
      return 'https://mainnet.mirrornode.hedera.com';
    case 'testnet':
      return 'https://testnet.mirrornode.hedera.com';
    case 'previewnet':
      return 'https://previewnet.mirrornode.hedera.com';
    default:
      throw new Error(`Unknown network: ${network}`);
  }
}
```

---

## 13. Docker Compose

```yaml
# docker-compose.yml
# Sustainable Explorer - Complete stack
# Usage: docker compose up -d

version: "3.9"

services:
  # ============================================================
  # PostgreSQL 16
  # ============================================================
  postgres:
    image: postgres:16-alpine
    container_name: explorer-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: sustainable_explorer
      POSTGRES_USER: explorer
      POSTGRES_PASSWORD: explorer_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./db/init.sql:/docker-entrypoint-initdb.d/01-init.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U explorer -d sustainable_explorer"]
      interval: 5s
      timeout: 5s
      retries: 5

  # ============================================================
  # Redict 7 (Redis-compatible)
  # ============================================================
  redict:
    image: registry.redict.io/redict:7-alpine
    container_name: explorer-redict
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redict_data:/data
    command: redict-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    healthcheck:
      test: ["CMD", "redict-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5

  # ============================================================
  # API Server (NestJS)
  # ============================================================
  api:
    build:
      context: .
      dockerfile: Dockerfile
      target: api
    container_name: explorer-api
    restart: unless-stopped
    environment:
      HEDERA_NET: mainnet
      DB_HOST: postgres
      DB_PORT: 5432
      DB_DATABASE: sustainable_explorer
      DB_USER: explorer
      DB_PASSWORD: explorer_password
      REDICT_HOST: redict
      REDICT_PORT: 6379
      API_PORT: 3030
      API_CORS_ORIGIN: http://localhost:8080
      LOG_LEVEL: info
    ports:
      - "3030:3030"
    depends_on:
      postgres:
        condition: service_healthy
      redict:
        condition: service_healthy

  # ============================================================
  # Worker (NestJS + BullMQ)
  # ============================================================
  worker:
    build:
      context: .
      dockerfile: Dockerfile
      target: worker
    container_name: explorer-worker
    restart: unless-stopped
    environment:
      HEDERA_NET: mainnet
      DB_HOST: postgres
      DB_PORT: 5432
      DB_DATABASE: sustainable_explorer
      DB_USER: explorer
      DB_PASSWORD: explorer_password
      REDICT_HOST: redict
      REDICT_PORT: 6379
      WORKER_TOPIC_CONCURRENCY: 5
      WORKER_MESSAGE_CONCURRENCY: 10
      WORKER_TOKEN_CONCURRENCY: 2
      WORKER_IPFS_CONCURRENCY: 3
      MV_REFRESH_INTERVAL: 60
      MIRROR_NODE_POLL_DELAY: 1000
      ORG_ROOT_TOPIC_ID: ""
      LOG_LEVEL: info
    depends_on:
      postgres:
        condition: service_healthy
      redict:
        condition: service_healthy

  # ============================================================
  # Frontend (Nuxt 3 + nginx)
  # ============================================================
  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend
    container_name: explorer-frontend
    restart: unless-stopped
    ports:
      - "8080:80"
    depends_on:
      - api

volumes:
  postgres_data:
  redict_data:
```

### 13.1 Dockerfile (multi-stage, shared between API and Worker)

```dockerfile
# Dockerfile
FROM node:20-alpine AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci --production=false
COPY . .
RUN npm run build

# API target
FROM node:20-alpine AS api
WORKDIR /app
COPY --from=base /app/dist ./dist
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/package.json ./
CMD ["node", "dist/api/main.js"]

# Worker target
FROM node:20-alpine AS worker
WORKDIR /app
COPY --from=base /app/dist ./dist
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/package.json ./
CMD ["node", "dist/worker/main.js"]
```

### 13.2 Frontend Dockerfile

```dockerfile
# Dockerfile.frontend
FROM node:20-alpine AS build
WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build -- --configuration production

FROM nginx:1.25-alpine
COPY --from=build /app/dist/sustainable-explorer/browser /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

### 13.3 nginx.conf (frontend proxy)

```nginx
server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;

    # Nuxt SPA/SSR routing
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Proxy API requests to backend
    location /api/v1/ {
        proxy_pass http://api:3030/api/v1/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # SSE support
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
    }
}
```

---

## 14. Project Structure

```
sustainable-explorer/
  package.json                    -- Root monorepo package
  tsconfig.json                   -- Base TypeScript config
  docker-compose.yml              -- Full stack orchestration
  Dockerfile                      -- API + Worker multi-stage build
  Dockerfile.frontend             -- Frontend build
  .env.example                    -- Environment variable template

  db/
    init.sql                      -- Full PostgreSQL schema (from section 6)
    migrations/                   -- TypeORM migration files
      001-initial-schema.ts
      002-materialized-views.ts
      003-business-views.ts
      004-search-triggers.ts

  src/
    shared/                       -- Code shared between API and Worker
      config/
        configuration.ts          -- Environment config with validation
        database.config.ts        -- TypeORM PostgreSQL config
        redict.config.ts          -- Redict connection config
        bullmq.config.ts          -- BullMQ queue definitions
      entities/                   -- TypeORM entities
        message.entity.ts
        message-cache.entity.ts
        topic-cache.entity.ts
        token-cache.entity.ts
        nft-cache.entity.ts
        policy-analytics.entity.ts
        document-analytics.entity.ts
        schema-analytics.entity.ts
        registry-analytics.entity.ts
        analytics-snapshot.entity.ts
        project-coordinates.entity.ts
        ipfs-file.entity.ts
        organization-config.entity.ts
        business-view.entity.ts
        synchronization-task.entity.ts
        log.entity.ts
      types/                      -- Copied from indexer-interfaces
        message-type.ts
        message-action.ts
        token-type.ts
        priority-status.ts
        business-view-type.ts
      interfaces/                 -- Copied from indexer-interfaces
        message.interface.ts
        raw-message.interface.ts
        raw-token.interface.ts
        raw-topic.interface.ts
        raw-nft.interface.ts
        relationships.interface.ts
        schema/
      utils/
        parser.ts                 -- Copied from indexer-worker-service
        ipfs-cid-patterns.ts      -- Copied from indexer-interfaces
        schema-helper.ts          -- Copied from indexer-interfaces

    api/                          -- API Server module
      main.ts                     -- NestJS bootstrap (API mode)
      api.module.ts               -- Root API module
      controllers/
        dashboard.controller.ts
        projects.controller.ts
        credits.controller.ts
        methodologies.controller.ts
        organizations.controller.ts
        analytics.controller.ts
        search.controller.ts
        sync-status.controller.ts
        events.controller.ts      -- SSE endpoint
      services/
        dashboard.service.ts
        projects.service.ts
        credits.service.ts
        methodologies.service.ts
        organizations.service.ts
        analytics.service.ts
        search.service.ts
        sync-status.service.ts
        cache.service.ts          -- Redict cache-aside wrapper
      guards/
        api-key.guard.ts          -- API key validation for public consumers (see api_keys table in schema)

        rate-limit.guard.ts       -- Rate limiting via Redict counters
      dto/
        pagination.dto.ts
        project.dto.ts
        credit.dto.ts
        methodology.dto.ts
        organization.dto.ts
        search.dto.ts

    worker/                       -- Worker module
      main.ts                     -- NestJS bootstrap (Worker mode)
      worker.module.ts            -- Root Worker module
      processors/
        topic-sync.processor.ts   -- mirror-node-topics queue
        message-process.processor.ts  -- mirror-node-messages queue
        token-sync.processor.ts   -- mirror-node-tokens queue
        ipfs-fetch.processor.ts   -- ipfs-files queue
        guardian-api-sync.processor.ts -- guardian-api-sync queue (optional)
        mv-refresh.processor.ts   -- maintenance/refresh-materialized-views
        business-view-builder.processor.ts  -- maintenance/build-business-views
      services/
        hedera.service.ts         -- Copied from indexer-worker-service
        ipfs.service.ts           -- Adapted from indexer-worker-service
        guardian-auth.service.ts  -- JWT token manager for Guardian API (login, auto-refresh)
        guardian-api.service.ts   -- Guardian API HTTP client (policies, schemas, tokens)
        org-discovery.service.ts  -- Organization topic tree discovery
        enrichment.service.ts     -- SQL-based enrichment (replaces 16 synchronizers)
        reconciliation.service.ts -- Merges Guardian API + Mirror Node data by consensus_timestamp
      schedulers/
        sync-scheduler.service.ts -- Initiates periodic topic/token/guardian-api sync jobs

  frontend/                       -- Nuxt 3 application
    package.json
    nuxt.config.ts                -- Nuxt configuration (SSR, API proxy, modules)
    tsconfig.json
    app.vue                       -- Root component (SSE init, global layout)
    pages/                        -- File-based routing (see section 10.1)
      index.vue                   -- Dashboard
      projects/
        index.vue                 -- Project list
        [id].vue                  -- Project detail
      credits/
        index.vue
        [tokenId].vue
      methodologies/
        index.vue
        [id].vue
      organizations/
        index.vue
        [did].vue
      analytics/
        index.vue
        issuance.vue
        geography.vue
      search.vue
      status.vue
    components/                   -- (see section 10.2)
      layout/
        AppHeader.vue
        AppFooter.vue
        AppSidebar.vue
      shared/
        DataTable.vue             -- TanStack Table wrapper
        SearchBar.vue
        StatCard.vue
        SkeletonLoader.vue
        EntityBadge.vue
        CursorPagination.vue
        ChartWrapper.vue
        SyncStatusBanner.vue
      projects/
      credits/
      analytics/
    composables/                  -- Vue 3 composables (replaces Angular services)
      useProjects.ts              -- TanStack Query: project data
      useCredits.ts               -- TanStack Query: credit data
      useMethodologies.ts         -- TanStack Query: methodology data
      useOrganizations.ts         -- TanStack Query: organization data
      useDashboard.ts             -- TanStack Query: dashboard data
      useSearch.ts                -- TanStack Query: search
      useSyncStatus.ts            -- TanStack Query: sync status
      useExplorerSSE.ts           -- SSE → TanStack Query invalidation
    types/                        -- TypeScript types for API responses
      project.ts
      credit.ts
      methodology.ts
      organization.ts
      api-response.ts
    plugins/
      tanstack-query.ts           -- TanStack Query plugin setup
    public/
    server/                       -- Nuxt server routes (optional BFF)
      api/                        -- Proxy or transform API responses if needed
```

---

## 15. Development Phases

### Phase 1: Core Sync Pipeline (3 weeks)

**Goal:** Mirror Node data flowing into PostgreSQL reliably.

**Week 1:**
- Project scaffolding (NestJS monorepo, TypeORM, BullMQ setup)
- PostgreSQL schema creation (all tables from section 6)
- Copy types/interfaces from `indexer-interfaces`
- Redict connection and BullMQ queue definitions
- Docker Compose for PostgreSQL + Redict

**Week 2:**
- Port `hedera-service.ts` (Mirror Node HTTP client)
- Port `parser.ts` (HCS message parsing)
- Implement `topic-sync.processor.ts` (mirror-node-topics queue)
- Implement `message-process.processor.ts` (mirror-node-messages queue)
- Implement `token-sync.processor.ts` (mirror-node-tokens queue)
- Topic discovery and `sync-scheduler.service.ts`

**Week 3:**
- Port `ipfs-service.ts` (IPFS gateway client)
- Implement `ipfs-fetch.processor.ts` (ipfs-files queue)
- Implement `mv-refresh.processor.ts` (materialized view refresh)
- Full-text search trigger verification
- End-to-end test: start worker against testnet, verify data in PostgreSQL
- Basic sync status logging

**Deliverable:** Worker process that continuously syncs Hedera testnet data into PostgreSQL.

### Phase 2: API + Business Views + Public API (3 weeks)

**Week 4:**
- NestJS API module setup with OpenAPI/Swagger decorators
- Implement `enrichment.service.ts` (SQL-based, replaces 16 synchronizers)
- Implement `business-view-builder.processor.ts`
- Business data mapping logic (section 7)
- Redict cache service
- `GET /api/v1/dashboard`
- `GET /api/v1/sync-status`

**Week 5:**
- All CRUD endpoints (projects, credits, methodologies, organizations)
- Search endpoint with tsvector
- Analytics endpoints
- SSE event system
- Cache invalidation via Pub/Sub

**Week 6:**
- Public API layer: `api_keys` table, API key guard, rate limiting via Redict
- Consistent response envelope (`data`, `meta`, `syncStatus`)
- OpenAPI docs at `/api/docs`
- CORS configuration
- API integration tests

**Deliverable:** Fully functional public REST API with Swagger docs, API keys, rate limiting, and caching.

### Phase 3: Frontend — Vue 3 + Nuxt 3 (3 weeks)

**Week 7:**
- Nuxt 3 project setup with TanStack Query plugin
- Shared components (DataTable with TanStack Table, SearchBar, StatCard, SkeletonLoader)
- Dashboard page with `useDashboard()` composable
- SSE integration (`useExplorerSSE()` → TanStack Query invalidation)

**Week 8:**
- Project list and detail pages with TanStack Query
- Credit list and detail pages
- Methodology list and detail pages
- Organization list and detail pages
- Search results page with debounced query
- Cursor-based pagination component

**Week 9:**
- Analytics pages (overview, issuance, geography/map)
- Sync status page
- Nuxt SSR for SEO-critical pages (dashboard, project list)
- Responsive design and polish
- End-to-end testing

**Deliverable:** Complete Sustainable Explorer UI with SSR, real-time updates, and TanStack-powered data management.

### Phase 4: Guardian API Integration + Org Prioritization (3 weeks)

**Week 10:**
- `guardian-auth.service.ts` (JWT token manager: login, auto-refresh)
- `guardian-api.service.ts` (HTTP client for Guardian API endpoints)
- `guardian-api-sync.processor.ts` (BullMQ queue)
- `reconciliation.service.ts` (merge Guardian API + Mirror Node data)
- Configuration: `GUARDIAN_API_URL`, `GUARDIAN_API_USERNAME`, `GUARDIAN_API_PASSWORD`

**Week 11:**
- Organization topic tree discovery (`org-discovery.service.ts`)
- BullMQ priority enforcement based on `ORG_ROOT_TOPIC_ID`
- `organization_config` table management
- Shared Redict configuration (`REDICT_DB`, `REDICT_KEY_PREFIX`)
- Test co-located mode with a running Guardian instance

**Week 12:**
- Advanced analytics (issuance trends, geographic distribution, org comparison)
- Performance optimization (query tuning, index analysis, cache TTL tuning)
- Production deployment documentation (standalone + co-located docker-compose variants)
- Load testing with mainnet data volumes
- Monitoring and alerting setup (health checks, queue metrics, Bull Board)

**Deliverable:** Production-ready Sustainable Explorer with Guardian API acceleration, organization-first sync, and dual deployment modes.

---

## Appendix: Key Differences from Existing Indexer

| Aspect | Existing Indexer | Sustainable Explorer |
|---|---|---|
| **Type** | Subsystem of Guardian (5 services) | Standalone application (1 codebase, 2 processes) |
| **Data source** | Mirror Node only | Mirror Node + IPFS (standalone) or + Guardian API (co-located) |
| **Auth required** | NATS internal service JWT | None (standalone) or Guardian JWT for published data (co-located) |
| **Deployment** | Must run within Guardian cluster | Standalone OR co-located (shares Redict, connects to Guardian API) |
| **Database** | MongoDB (MikroORM) | PostgreSQL (TypeORM) |
| **Message broker** | NATS (RPC + Pub/Sub) | None (BullMQ + Redict Pub/Sub) |
| **Job management** | Custom `Job`/`Jobs` polling loop | BullMQ (retry, priority, concurrency, DLQ) |
| **Enrichment** | 16 cron synchronizers loading full datasets | SQL materialized views + targeted enrichment jobs |
| **Full-text search** | `$regex` on concatenated string (O(n)) | `tsvector` with GIN index (O(log n)) |
| **Aggregations** | N+1 count queries per detail view | Single SELECT from materialized views |
| **Relationship graph** | Recursive async N+1 findOne calls | Single recursive CTE query |
| **Caching** | None | Redict with TTL + event-driven invalidation |
| **Real-time updates** | None (poll-based frontend) | SSE via Redict Pub/Sub + TanStack Query invalidation |
| **Frontend** | Angular 18 (indexer-frontend) | Vue 3 + Nuxt 3 + TanStack Query/Table |
| **SSR/SEO** | Not supported | Nuxt 3 SSR built-in |
| **Public API** | No authentication, no docs | API keys, rate limiting, OpenAPI/Swagger docs |
| **API versioning** | None (`/entities/*`) | Versioned (`/api/v1/*`) |
| **Business domain** | Raw blockchain entities only | Mapped to Projects, Credits, Methodologies, Organizations |
| **Frontend** | Generic entity browser | Sustainability-focused explorer |

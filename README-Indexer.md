# Guardian Indexer — Data Architecture

The indexer is a **standalone subsystem** of 5 services that indexes Hedera blockchain data into MongoDB for fast querying. It operates independently from the main Guardian services.

## Services

| Folder | Purpose |
|--------|---------|
| `indexer-interfaces/` | TypeScript types, enums, interfaces |
| `indexer-common/` | Shared DB models, entities, NATS message defs, utilities |
| `indexer-worker-service/` | Background worker — fetches data from Hedera Mirror Node |
| `indexer-service/` | Query engine — cron-based synchronizers + NATS handlers |
| `indexer-api-gateway/` | REST HTTP API (port 3021) — proxies to indexer-service via NATS |
| `indexer-frontend/` | Angular UI for browsing indexed data |
| `indexer-web-proxy/` | Web proxy for deployment |

## Data Flow Pipeline

```
Hedera Blockchain (Topics & Tokens)
          │
          ▼
  Hedera Mirror Node REST API
  (/topics/{id}/messages, /tokens/{id}, /tokens/{id}/nfts)
          │
          ▼
┌─────────────────────────────────────────────┐
│  INDEXER-WORKER-SERVICE                     │
│                                             │
│  4 concurrent job queues:                   │
│  ├─ Topics (5 concurrent, 1s delay)         │
│  ├─ Messages (10 concurrent, 1s delay)      │
│  ├─ Tokens (2 concurrent, 1s delay)         │
│  └─ Files (1 concurrent, 24h cycle)         │
│                                             │
│  HederaService → fetch from Mirror Node     │
│  TopicService  → raw msgs → MessageCache    │
│  MessageService→ parse, load IPFS docs      │
│  TokenService  → token metadata + NFTs      │
│  FileService   → IPFS file operations       │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  MONGODB (Collections)                      │
│                                             │
│  Cache Layer (worker writes):               │
│  ├─ message_cache  (raw incoming msgs)      │
│  ├─ topic_cache    (sync state per topic)   │
│  ├─ token_cache    (token sync state)       │
│  ├─ nft_cache      (NFT serial metadata)    │
│  ├─ priority_queue (priority load tasks)    │
│  └─ synchronization_task (job locks)        │
│                                             │
│  Data Layer (service reads/enriches):       │
│  ├─ message     (parsed entities — the      │
│  │               main table for everything) │
│  ├─ analytics   (daily aggregated stats)    │
│  ├─ project_coordinates (geo data)          │
│  ├─ logs        (error logs)                │
│  └─ GridFS      (large file storage)        │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  INDEXER-SERVICE (Cron Synchronizers)       │
│                                             │
│  15+ scheduled sync tasks that enrich the   │
│  message collection with analytics:         │
│  ├─ SyncAnalytics    (daily counts)         │
│  ├─ SyncPolicies     (policy parsing)       │
│  ├─ SyncSchemas      (schema extraction)    │
│  ├─ SyncVCs / SyncVPs (document indexing)   │
│  ├─ SyncDid          (DID documents)        │
│  ├─ SyncRegistries   (account data)         │
│  ├─ SyncModules / SyncTools                 │
│  ├─ SyncContracts / SyncTopics              │
│  ├─ SyncLabels / SyncFormulas               │
│  └─ SyncProjects / SyncRoles               │
│                                             │
│  NATS handlers for queries:                 │
│  ├─ EntityService   (CRUD by type)          │
│  ├─ SearchService   (full-text search)      │
│  ├─ FiltersService  (dynamic filters)       │
│  ├─ LandingService  (dashboard analytics)   │
│  ├─ AnalyticsService(statistics)            │
│  └─ LoadingQueueService (sync progress)     │
└──────────────────┬──────────────────────────┘
                   │ NATS RPC
                   ▼
┌─────────────────────────────────────────────┐
│  INDEXER-API-GATEWAY (port 3021)            │
│                                             │
│  REST endpoints → NATS → indexer-service:   │
│  GET  /search?search=...                    │
│  GET  /entities/{type}                      │
│  GET  /entities/{type}/{id}                 │
│  GET  /entities/{type}/{id}/relationships   │
│  GET  /filters                              │
│  GET  /landing/analytics                    │
│  GET  /analytics                            │
│  GET  /entities/ipfs/{cid}                  │
│  POST /artifacts/chunks                     │
│  + 50 more endpoints                        │
└─────────────────────────────────────────────┘
```

## Data Models

All entities are MongoDB collections managed by MikroORM, defined in `indexer-common/src/entity/`.

### `Message` — The Central Entity

Every Guardian object (policy, schema, VC, VP, DID, token, module, tool, contract) is stored as a `Message` row differentiated by `type`.

| Field | Description |
|-------|-------------|
| `consensusTimestamp` | Primary key from Hedera (unique) |
| `topicId` | Hedera topic ID |
| `type` | Entity type — Policy, Schema, VC, VP, DID, Token, Module, Tool, etc. |
| `action` | What happened — Create, Publish, Update, etc. |
| `status` | Processing status — LOADING → LOADED |
| `files` | Array of IPFS CIDs for associated documents |
| `documents` | Parsed document content |
| `analytics` | Embedded object with `textSearch` (indexed), schema info, token counts |
| `owner` | DID of the entity owner |

### `MessageCache` — Raw Ingestion Buffer

Temporary storage for messages being fetched from Mirror Node before parsing.

| Field | Description |
|-------|-------------|
| `consensusTimestamp` | Hedera timestamp |
| `topicId` | Source topic |
| `message` | Raw message content |
| `status` | Processing progress |
| `chunkId` | For multi-part messages |
| `priorityDate` / `priorityStatus` | Priority loading tracking |

### `TopicCache` — Topic Sync State

One row per topic, tracks how far the worker has synced.

| Field | Description |
|-------|-------------|
| `topicId` | Unique topic identifier |
| `messages` | Last sequence number fetched |
| `hasNext` | Pagination link for Mirror Node |
| `status` | Sync status |
| `priorityDate` / `priorityStatus` | Priority loading tracking |

### `TokenCache` — Token Sync State

| Field | Description |
|-------|-------------|
| `tokenId` | Unique token identifier |
| `name` / `symbol` | Token metadata |
| `type` | FUNGIBLE or NON_FUNGIBLE_UNIQUE |
| `totalSupply` | Total token supply |
| `serialNumber` | Progress tracking for NFT enumeration |

### `NftCache` — Individual NFTs

| Field | Description |
|-------|-------------|
| `tokenId` + `serialNumber` | Composite unique key |
| `metadata` | NFT metadata content |

### `Analytics` — Daily Aggregates

| Field | Description |
|-------|-------------|
| `registries` / `methodologies` / `projects` | Entity counts |
| `totalIssuance` / `totalSerialized` / `totalFungible` | Token stats |
| `date` | Aggregation date |

### `PriorityQueue` — On-Demand Loading

When a user requests data that isn't synced yet, a priority entry is created. The worker picks these up before regular sync jobs.

### `SynchronizationTask` — Distributed Locks

Single `taskName` (unique) field prevents duplicate sync jobs across instances.

## How Sync Works

### 1. Topic Sync (Worker)

The worker's `TopicService` polls Hedera Mirror Node at `GET /topics/{topicId}/messages` in batches of 100. It stores raw messages in `MessageCache`, tracks progress in `TopicCache.messages` (last sequence number), and follows `hasNext` pagination links.

**Source:** `indexer-worker-service/src/services/topic-service.ts`

### 2. Message Processing (Worker)

`MessageService` picks up `MessageCache` entries with `status=LOADING`, parses JSON content, loads IPFS documents referenced by file hashes, handles multi-chunk message assembly, and writes the final parsed result to the `Message` collection with `status=LOADED`.

**Source:** `indexer-worker-service/src/services/message-service.ts`

### 3. Token Sync (Worker)

`TokenService` fetches token metadata via `GET /tokens/{tokenId}` and NFT serials via `GET /tokens/{tokenId}/nfts`, storing results in `TokenCache` and `NftCache`.

**Source:** `indexer-worker-service/src/services/token-service.ts`

### 4. Enrichment Sync (Service — Cron)

The `indexer-service` runs 15+ cron-scheduled synchronizers (configurable via `SYNC_*_MASK` env vars) that read from the `Message` collection and enrich records with analytics data, text search indexes, and relationship mappings.

**Source:** `indexer-service/src/helpers/synchronizers/synchronize-all.ts`

### 5. Priority Loading

When the frontend needs data that hasn't been synced yet, it adds an entry to `PriorityQueue`. The worker checks priority entries first. On completion, it emits `ON_PRIORITY_DATA_LOADED` via NATS to notify the service layer.

## How APIs Work

### Communication Chain

```
HTTP Client → REST (API Gateway) → NATS RPC → indexer-service → MongoDB → response back
```

The API Gateway is a thin NestJS HTTP layer. Each endpoint serializes the request into a NATS message pattern (e.g., `IndexerMessageAPI.GET_POLICIES`), sends it to the `INDEXER_SERVICES` queue group, and returns the response.

### NATS Message Patterns

Defined in `indexer-common/src/messages/message-api.ts`:

| Pattern | Description |
|---------|-------------|
| `GET_REGISTRIES` / `GET_REGISTRY` | Standard Registry accounts |
| `GET_POLICIES` / `GET_POLICY` | Policy data |
| `GET_SCHEMAS` / `GET_SCHEMA` | Schema definitions |
| `GET_VC_DOCUMENTS` / `GET_VC_DOCUMENT` | Verifiable Credentials |
| `GET_VP_DOCUMENTS` / `GET_VP_DOCUMENT` | Verifiable Presentations |
| `GET_DID_DOCUMENTS` / `GET_DID_DOCUMENT` | DID documents |
| `GET_TOKENS` / `GET_TOKEN` | Token metadata |
| `GET_NFTS` / `GET_NFT` | NFT data |
| `GET_SEARCH_API` | Full-text search (regex on `analytics.textSearch`) |
| `GET_RELATIONSHIPS` | Entity relationship graph |
| `GET_LANDING_ANALYTICS` | Dashboard statistics |
| `GET_DATA_LOADING_PROGRESS` | Sync progress |

### Search Implementation

Uses MongoDB `$regex` on the `analytics.textSearch` field (which has a sparse text index). Case-insensitive matching with pagination support.

## Configuration

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `DB_HOST` / `DB_DATABASE` | MongoDB connection |
| `HEDERA_NET` | Network — testnet, mainnet, or localnode |
| `MQ_ADDRESS` | NATS broker address |
| `GUARDIAN_ENV` | DB name prefix: `{ENV}_{NET}_{DB}` |
| `SYNC_ANALYTICS_MASK` | Cron for analytics sync |
| `SYNC_POLICIES_MASK` | Cron for policy sync |
| `SYNC_SCHEMAS_MASK` | Cron for schema sync |
| `SYNC_VC_DOCUMENTS_MASK` | Cron for VC document sync |
| `SYNC_VP_DOCUMENTS_MASK` | Cron for VP document sync |
| `SYNC_DID_DOCUMENTS_MASK` | Cron for DID document sync |
| `SYNC_MODULES_MASK` | Cron for module sync |
| `SYNC_REGISTRIES_MASK` | Cron for registry sync |
| `SYNC_ROLES_MASK` | Cron for role sync |
| `SYNC_TOOLS_MASK` | Cron for tool sync |
| `MESSAGE_JOB_COUNT` | Concurrent message processors (default 10) |
| `TOPIC_JOB_COUNT` | Concurrent topic fetchers (default 5) |
| `TOKEN_JOB_COUNT` | Concurrent token fetchers (default 2) |

### Docker

```bash
docker-compose -f docker-compose-indexer.yml up -d --build
```

## Key Files Reference

| What | Path |
|------|------|
| All entities | `indexer-common/src/entity/*.ts` |
| DB config | `indexer-common/src/db-helper/db-config.ts` |
| NATS patterns | `indexer-common/src/messages/message-api.ts` |
| Mirror Node client | `indexer-worker-service/src/loaders/hedera-service.ts` |
| Topic sync | `indexer-worker-service/src/services/topic-service.ts` |
| Message processing | `indexer-worker-service/src/services/message-service.ts` |
| Token sync | `indexer-worker-service/src/services/token-service.ts` |
| Worker init (job queues) | `indexer-worker-service/src/app.ts` |
| Sync orchestrator | `indexer-service/src/helpers/synchronizers/synchronize-all.ts` |
| Entity query handler | `indexer-service/src/api/entities.service.ts` |
| Search handler | `indexer-service/src/api/search.service.ts` |
| REST endpoints | `indexer-api-gateway/src/api/services/*.ts` |
| Swagger docs | `swagger-indexer.yaml` |

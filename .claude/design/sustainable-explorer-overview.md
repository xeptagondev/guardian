# Sustainable Explorer — Architecture Overview

**Date:** 2026-03-20
**Status:** Pending Approval
**Version:** 1.0

> This is a condensed overview. Full technical details (SQL schemas, code examples, Docker configs) are in `sustainable-explorer-final-design.md`.

---

## 1. What is Sustainable Explorer?

A standalone application that indexes Hedera Guardian blockchain data and presents it through a sustainability-focused business lens — transforming raw HCS messages and IPFS documents into **Projects, Credits, Methodologies, Organizations, and Retirements**.

**Two deployment modes:**

- **Standalone** — connect to any Hedera network using only public endpoints (Mirror Node + IPFS). No Guardian instance required.
- **Co-located with Guardian** — optionally connect to a Guardian REST API for faster published data, and share existing Redict infrastructure.

---

## 2. Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend API** | NestJS 11, TypeScript 5.5+ |
| **Database** | PostgreSQL 16 (materialized views, tsvector search, recursive CTEs, JSONB) |
| **Cache / Queues** | Redict 7 (Redis-compatible) — own instance or shared with Guardian |
| **Job Management** | BullMQ 5 (retry, priority, concurrency, dead letter queues) |
| **ORM** | TypeORM 0.3.x |
| **Frontend** | Vue 3 + Nuxt 3 (SSR) + TanStack Query 5 + TanStack Table 8 |
| **Runtime** | Node.js 20 LTS |
| **Containerization** | Docker + Docker Compose |

---

## 3. Architecture

```
     PUBLIC DATA SOURCES                         OPTIONAL
     (no auth required)                          (JWT auth)

  +-----------------------+  +----------------+  +-------------------+
  | Hedera Mirror Node    |  | IPFS Gateways  |  | Guardian API      |
  | /topics/{id}/messages |  | /ipfs/{cid}    |  | /policies         |
  | /tokens/{id}          |  |                |  | /schemas          |
  | /tokens/{id}/nfts     |  |                |  | /tokens           |
  +-----------+-----------+  +-------+--------+  +---------+---------+
              |                      |                      |
              +----------+-----------+----------+-----------+
                         |                      |
  +----------------------v----------------------v-----------+
  |                  SUSTAINABLE EXPLORER                    |
  |                                                         |
  |  API Server (NestJS)        Worker(s) (NestJS + BullMQ) |
  |  - REST /api/v1/*           - mirror-node-topics        |
  |  - SSE events               - mirror-node-messages      |
  |  - OpenAPI/Swagger          - mirror-node-tokens        |
  |  - API key auth             - ipfs-files                |
  |  - Rate limiting            - guardian-api-sync         |
  |                             - maintenance/*             |
  |                                                         |
  |  +-------------+       +-------------+                  |
  |  | PostgreSQL  |       |   Redict    |                  |
  |  | Tables      |       | BullMQ jobs |                  |
  |  | Mat. views  |       | Cache       |                  |
  |  | tsvector    |       | Pub/Sub     |                  |
  |  +-------------+       +-------------+                  |
  +---------------------------------------------------------+
```

**Two processes, one codebase:**
- **API Server** — handles HTTP requests, serves REST API + SSE events
- **Worker** — processes BullMQ jobs (Mirror Node sync, IPFS fetch, Guardian API sync, maintenance)

---

## 4. Data Sources

### 4.1 Hedera Mirror Node (always enabled, no auth)

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/topics/{id}/messages` | Fetch HCS messages (paginated, incremental by sequence number) |
| `GET /api/v1/tokens/{id}` | Token metadata (name, symbol, supply, type) |
| `GET /api/v1/tokens/{id}/nfts` | NFT serial enumeration |

### 4.2 IPFS Gateways (always enabled, no auth)

Fetches document content referenced by IPFS CIDs in HCS messages. Multiple gateways tried in order (ipfs.io, cloudflare-ipfs.com, gateway.pinata.cloud). Unreliable — BullMQ retries with exponential backoff.

### 4.3 Guardian API (optional, JWT auth)

When co-located with Guardian, polls published data for faster ingestion. Guardian has already-parsed documents — no IPFS fetch needed.

| Endpoint | Polling Frequency |
|----------|-------------------|
| `GET /policies?status=PUBLISHED` | 30 seconds |
| `GET /schemas?status=PUBLISHED` | 60 seconds |
| `GET /tokens` | 60 seconds |
| `GET /modules?status=PUBLISHED` | 120 seconds |
| `GET /tools?status=PUBLISHED` | 120 seconds |

**Auth:** Dedicated read-only user with JWT auto-refresh (login once, refresh access token every 50s).

### 4.4 Data Source Precedence

```
Document content resolution order:

1. PostgreSQL: already have content?  → YES → skip
                                      → NO  ↓
2. Guardian API enabled + self-org?   → YES → fetch (fast, pre-parsed)
                                      → NO  ↓
3. IPFS gateways                      → fetch (slow, retry with backoff)
```

- **Mirror Node** is authoritative for: consensus timestamps, sequence numbers, token supply
- **Guardian API** is authoritative for: document content (already parsed)
- **IPFS** is the fallback for document content when Guardian API is unavailable
- **Deduplication** by `consensus_timestamp` — records merge from multiple sources

### 4.5 Redict (own or shared)

When co-located with Guardian, share the existing Redict instance using a separate DB number and key prefix (`se:`) to avoid collisions.

---

## 5. Data Pipeline (BullMQ Queues)

BullMQ manages **which work to do, when, and how many at once**. Job metadata lives in Redict; actual data lives in PostgreSQL.

| Queue | Concurrency | Retry | Timeout | Purpose |
|-------|-------------|-------|---------|---------|
| `mirror-node-topics` | 5 | 3x exponential | 2 min | Fetch HCS messages per topic |
| `mirror-node-messages` | 10 | 3x fixed 5s | 1 min | Parse raw messages, classify type, extract CIDs |
| `mirror-node-tokens` | 2 | 3x exponential | 2 min | Fetch token metadata + NFT serials |
| `ipfs-files` | 3 | 5x exponential | 3 min | Fetch documents from IPFS gateways |
| `guardian-api-sync` | 1 | 3x fixed 30s | 2 min | Poll Guardian API for published data (optional) |
| `maintenance/refresh-mvs` | 1 (singleton) | — | 5 min | Refresh materialized views every 60s |
| `maintenance/build-biz-views` | 1 | — | 10 min | Build business domain views after sync |

**Organization prioritization:** Jobs for org topics get `priority: 1`, network topics get `priority: 10`. Configured via `ORG_ROOT_TOPIC_ID` env var.

**Job chain:**
```
topic-sync → message-process → ipfs-fetch
                             → token-sync (if Token message)
                             → topic-sync (if Topic message — discovers child topics)
```

---

## 6. Data Model (PostgreSQL)

### Core Tables

| Table | Purpose |
|-------|---------|
| `message` | Central table — all entity types (30+) differentiated by `type`. JSONB `options`/`documents`. `tsvector` for full-text search. `data_source` tracks provenance. |
| `policy_analytics` | Policy-specific computed data (registry, VC/VP counts, tools, tokens, hash) |
| `document_analytics` | VC/VP-specific data (linked policy, schema, issuer) |
| `schema_analytics` | Schema metadata (child schemas, properties) |
| `registry_analytics` | Registry metadata (DID, org name, registrant topic) |
| `business_view` | Materialized business domain (Projects, Credits, Methodologies, Organizations) |
| `organization_config` | Configured orgs for prioritized sync |
| `api_keys` | Public API key management (hash, rate limit, permissions) |

### Cache Tables (worker writes)

| Table | Purpose |
|-------|---------|
| `message_cache` | Raw HCS messages before parsing |
| `topic_cache` | Sync watermark per topic (last sequence number) |
| `token_cache` | Token metadata + NFT enumeration progress |
| `nft_cache` | Individual NFT serial metadata |
| `ipfs_files` | IPFS document content (replaces MongoDB GridFS) |

### Materialized Views (replace 16 cron synchronizers)

| View | Replaces | Refresh |
|------|----------|---------|
| `mv_registry_activity` | 9 sequential count queries in `getRegistry()` | 60s |
| `mv_policy_activity` | 8 sequential count queries in `getPolicy()` | 60s |
| `mv_topic_activity` | 13 sequential count queries in `getTopic()` | 120s |
| `mv_landing_analytics` | Daily analytics collection | 300s |

### Key PostgreSQL Features Used

- **`tsvector` + GIN index** — replaces MongoDB `$regex` full-text search (O(n) → O(log n))
- **Materialized views** — replaces N+1 count queries with single SELECT
- **Recursive CTEs** — replaces N+1 relationship graph traversal
- **JSONB** — flexible fields (options, documents) with GIN indexes
- **`INSERT...ON CONFLICT`** — idempotent upserts for dual-source reconciliation
- **Triggers** — auto-update search vector on INSERT/UPDATE

---

## 7. Business Data Mapping

Raw blockchain messages mapped to sustainability domain:

| Raw Message Type | Business Domain | Key Mapping |
|-----------------|----------------|-------------|
| `STANDARD_REGISTRY` | **Organization** | `options.did` → orgId, `OrganizationName` → name |
| `INSTANCE_POLICY` + `PublishPolicy` | **Methodology** | Policy name/description, schema count |
| `VC_DOCUMENT` (project schema) | **Project** | credentialSubject → name, location, vintage |
| `VC_DOCUMENT` (mint-related) | **Carbon Credit** | linked token via `analytics.tokenId` |
| `VP_DOCUMENT` + `CreateVP` | **Verification/Issuance** | VP wrapping mint VCs = issuance event |
| `TOKEN` (FT) | **Credit Token** | `totalSupply` / `decimals` = credit volume |
| `TOKEN` (NFT) + `NftCache` | **Serialized Credit** | Each NFT serial = one credit unit |
| `CONTRACT` | **Retirement Contract** | Smart contract for credit retirement |

---

## 8. Caching Strategy (Redict)

| Cache Key Pattern | TTL | Purpose |
|-------------------|-----|---------|
| `se:dashboard:{orgDid}` | 30s | Pre-computed dashboard aggregates |
| `se:list:{type}:{hash(filters)}` | 60s | Paginated list results |
| `se:detail:{consensusTimestamp}` | 5 min | Entity details |
| `se:search:{hash(query)}` | 60s | Search results (expensive tsvector queries) |
| `se:sync-status` | 10s | Sync progress |

**Invalidation:** BullMQ job completion → publish to Redict Pub/Sub channel `se:events` → subscribers invalidate relevant cache keys.

**Frontend (TanStack Query)** handles its own in-memory caching with `staleTime` and `refetchInterval`, reducing Redict load for the UI. Redict caching remains important for **public API consumers** who don't have TanStack.

---

## 9. Public API

### Design Principles

- All endpoints under `/api/v1/` (versioned)
- OpenAPI/Swagger docs at `/api/docs`
- API key authentication for external consumers (`X-API-Key` header or `?apiKey=` query param)
- Rate limiting per API key via Redict (default 100 req/min)
- Internal frontend (same-origin) — no API key required
- Consistent response envelope: `{ data, meta: { page, limit, total, cursor, hasMore }, syncStatus }`
- Cursor-based pagination using `consensus_timestamp`
- SSE events at `GET /api/v1/events`

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/dashboard` | Aggregated stats, recent activity, top organizations, sync status |
| `GET /api/v1/projects` | Paginated project list with filters (methodology, org, status) |
| `GET /api/v1/projects/:id` | Project detail with credits, methodology, verification status |
| `GET /api/v1/credits` | Credit/token list with filters |
| `GET /api/v1/credits/:tokenId` | Credit detail with mint history |
| `GET /api/v1/methodologies` | Methodology list (policies as business entities) |
| `GET /api/v1/methodologies/:id` | Methodology detail with projects, schemas, stats |
| `GET /api/v1/organizations` | Organization list |
| `GET /api/v1/organizations/:did` | Organization detail with activity summary |
| `GET /api/v1/analytics/overview` | Time-series analytics (period-based) |
| `GET /api/v1/analytics/credits-by-methodology` | Credit breakdown by methodology |
| `GET /api/v1/analytics/credits-by-project` | Credit breakdown by project |
| `GET /api/v1/search` | Full-text search across all entity types |
| `GET /api/v1/sync-status` | Current sync progress |
| `GET /api/v1/events` | SSE stream (sync-progress, new-project, new-credit, views-updated) |

---

## 10. Frontend (Vue 3 + Nuxt 3 + TanStack)

### Why This Stack

- **Nuxt 3** — SSR built-in (SEO for public explorer), file-based routing, code splitting
- **TanStack Query** — data fetching + caching + deduplication + background refresh out of the box
- **TanStack Table** — headless sortable/filterable/paginated tables
- **Vue 3 Composition API** — simpler than Angular, smaller bundle (~50KB vs ~150KB)

### Key Patterns

- **Composables** (`useProjects`, `useDashboard`, `useSearch`) wrap TanStack Query with `staleTime`, `refetchInterval`, `keepPreviousData`
- **SSE → Query Invalidation** — `useExplorerSSE()` watches server events and calls `queryClient.invalidateQueries()` per event type
- **Three-tier loading** — automatic via TanStack: skeleton (first load) → cached (stale) → background refresh
- **SSR** — `useAsyncData` for SEO-critical pages (dashboard, project list); TanStack Query for interactive pages

### Routes

```
/                          Dashboard
/projects                  Project list
/projects/:id              Project detail
/credits                   Credit list
/credits/:tokenId          Credit detail
/methodologies             Methodology list
/methodologies/:id         Methodology detail
/organizations             Organization list
/organizations/:did        Organization detail
/analytics                 Analytics overview
/analytics/issuance        Issuance charts
/analytics/geography       Map view
/search                    Search results
/status                    Sync dashboard
```

---

## 11. Code Reuse from Existing Indexer

| Strategy | Files | Why |
|----------|-------|-----|
| **COPY** (minimal changes) | `indexer-interfaces/` (all types/enums), `hedera-service.ts` (Mirror Node client), `parser.ts` (HCS message parsing — 30+ entity types), `ipfs-service.ts` | Zero DB coupling, pure domain knowledge |
| **STUDY & PORT** (extract logic, rewrite as SQL) | Synchronizer algorithms (SR-finding, VC-to-policy linking, relationship traversal), chunk reassembly, concurrency patterns | Valuable domain logic trapped in MongoDB CRUD |
| **REWRITE** (not worth adapting) | DB layer, search, API, job queues, frontend | 60% of codebase is MongoDB glue code |

---

## 12. Configuration

### Required (both modes)

| Variable | Default | Description |
|----------|---------|-------------|
| `HEDERA_NET` | `testnet` | Network: mainnet, testnet, previewnet |
| `HEDERA_MIRROR_NODE_URL` | Auto from `HEDERA_NET` | Mirror Node base URL |
| `DB_HOST` / `DB_PORT` / `DB_DATABASE` | `localhost` / `5432` / `sustainable_explorer` | PostgreSQL connection |
| `DB_USER` / `DB_PASSWORD` | — | PostgreSQL credentials |
| `REDICT_HOST` / `REDICT_PORT` | `localhost` / `6379` | Redict connection |
| `API_PORT` | `3030` | API server port |

### Optional — Organization Prioritization

| Variable | Default | Description |
|----------|---------|-------------|
| `ORG_ROOT_TOPIC_ID` | empty | Root topic for prioritized org sync |

### Optional — Guardian API (co-located mode)

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARDIAN_API_URL` | empty | Guardian API URL (empty = standalone mode) |
| `GUARDIAN_API_USERNAME` | — | Dedicated read-only user |
| `GUARDIAN_API_PASSWORD` | — | User password |
| `GUARDIAN_API_POLICY_INTERVAL` | `30` | Polling interval (seconds) |

### Optional — Redict Sharing

| Variable | Default | Description |
|----------|---------|-------------|
| `REDICT_DB` | `0` | Use 1+ when sharing with Guardian |
| `REDICT_KEY_PREFIX` | `se:` | Namespace to avoid collisions |

### Worker Tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `WORKER_TOPIC_CONCURRENCY` | `5` | Concurrent topic sync jobs |
| `WORKER_MESSAGE_CONCURRENCY` | `10` | Concurrent message processing jobs |
| `WORKER_TOKEN_CONCURRENCY` | `2` | Concurrent token sync jobs |
| `WORKER_IPFS_CONCURRENCY` | `3` | Concurrent IPFS fetch jobs |
| `MV_REFRESH_INTERVAL` | `60` | Materialized view refresh (seconds) |

---

## 13. Development Phases (12 weeks)

### Phase 1: Core Sync Pipeline (Weeks 1–3)

- Project scaffolding (NestJS, TypeORM, BullMQ, Docker Compose)
- PostgreSQL schema + materialized views + search triggers
- Port `hedera-service.ts`, `parser.ts`, `ipfs-service.ts`
- Implement all Mirror Node BullMQ processors (topics, messages, tokens, IPFS)
- End-to-end test: worker syncs testnet data into PostgreSQL

**Deliverable:** Worker process continuously syncing Hedera data into PostgreSQL.

### Phase 2: API + Business Views + Public API (Weeks 4–6)

- REST API with all CRUD endpoints, search, analytics, SSE
- SQL-based enrichment (replaces 16 cron synchronizers)
- Business view builder (Projects, Credits, Methodologies, Organizations)
- Public API layer: API keys, rate limiting, OpenAPI/Swagger docs
- Redict caching + Pub/Sub invalidation

**Deliverable:** Fully functional public REST API with docs, auth, and caching.

### Phase 3: Frontend — Nuxt 3 + TanStack (Weeks 7–9)

- Nuxt 3 setup with TanStack Query/Table plugins
- All pages: dashboard, projects, credits, methodologies, organizations, analytics, search, status
- SSE → TanStack Query invalidation for real-time updates
- Nuxt SSR for SEO-critical pages
- Responsive design + end-to-end testing

**Deliverable:** Complete Sustainable Explorer UI with SSR and real-time updates.

### Phase 4: Guardian API Integration + Org Prioritization (Weeks 10–12)

- Guardian auth manager (JWT login, auto-refresh)
- Guardian API sync processor + reconciliation service
- Organization topic tree discovery + BullMQ priority enforcement
- Shared Redict configuration for co-located mode
- Performance optimization, load testing, production deployment docs

**Deliverable:** Production-ready with Guardian API acceleration, org-first sync, dual deployment modes.

---

## 14. Key Differences from Existing Indexer

| Aspect | Existing Indexer | Sustainable Explorer |
|--------|-----------------|---------------------|
| **Type** | 5 co-dependent services in Guardian cluster | 1 codebase, 2 processes, standalone or co-located |
| **Database** | MongoDB (MikroORM) | PostgreSQL (TypeORM) |
| **Message broker** | NATS | None (BullMQ + Redict Pub/Sub) |
| **Job management** | Custom polling loop | BullMQ (retry, priority, DLQ) |
| **Enrichment** | 16 cron synchronizers loading full datasets | SQL materialized views |
| **Search** | `$regex` on concatenated string — O(n) | `tsvector` + GIN index — O(log n) |
| **Aggregations** | N+1 count queries per detail view | Single SELECT from materialized view |
| **Relationships** | Recursive N+1 findOne calls | Single recursive CTE |
| **Caching** | None | Redict + TanStack Query |
| **Real-time** | None (poll-based frontend) | SSE via Redict Pub/Sub |
| **Frontend** | Angular 18 | Vue 3 + Nuxt 3 (SSR) + TanStack |
| **Public API** | No auth, no docs, no versioning | API keys, rate limiting, OpenAPI, `/api/v1/*` |
| **Data domain** | Raw blockchain entities | Business domain (Projects, Credits, Methodologies) |
| **Deployment** | Must run within Guardian cluster | Standalone OR co-located with Guardian |

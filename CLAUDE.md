# CLAUDE.md — Hedera Guardian Codebase Context

## Project Overview

**Guardian** is a modular open-source solution by Hashgraph/Envision Blockchain for environmental asset tokenization on the Hedera network. At its heart is a **Policy Workflow Engine (PWE)** that enables digital Measurement, Reporting, and Verification (MRV) workflows. Guardian manages the full lifecycle of Verifiable Credentials (VCs), Verifiable Presentations (VPs), Decentralized Identifiers (DIDs), schemas, tokens, and smart contracts — all anchored to the Hedera Consensus Service (HCS) and Hedera Token Service (HTS).

- **Version**: 3.5.0
- **License**: Apache-2.0
- **Package Manager**: Yarn 1.22.21 (workspaces)
- **Node.js**: v20.19
- **Primary Language**: TypeScript (ES modules, `"type": "module"`)

> **Note**: The `sustainable-explorer/` directory is a **separate project** (Sustainability Explorer) and is NOT part of the Guardian codebase or architecture. Do not modify it when working on Guardian, and vice versa.

---

## Architecture Overview

Guardian is a **microservices architecture** with services communicating via **NATS message broker**. Data is stored in **MongoDB v6** with **MikroORM**. Secrets are managed via pluggable providers (database, HashiCorp Vault, AWS, Azure, GCP). IPFS is used for document storage (via Storacha/web3storage, Filebase, or local node).

```
┌─────────────────────────────────────────────────────────────────┐
│                        web-proxy (Nginx)                        │
│                     localhost:3000 → :80                         │
├─────────────────┬───────────────────────────────────────────────┤
│   frontend      │              api-gateway (:3002)              │
│   (Angular 18)  │         NestJS + Fastify REST API             │
│   localhost:4200 │         Swagger at /api-docs                  │
└────────┬────────┴──────────────┬────────────────────────────────┘
         │                       │ (NATS message broker :4222)
         │        ┌──────────────┼──────────────────┐
         │        │              │                  │
    ┌────▼────┐ ┌─▼──────────┐ ┌▼───────────────┐ ┌▼──────────────┐
    │  auth   │ │  guardian   │ │ policy-service  │ │ worker-service│
    │ service │ │  service   │ │ (policy engine) │ │  (2 replicas) │
    └─────────┘ └────────────┘ └─────────────────┘ └───────────────┘
         │              │              │                   │
    ┌────▼────┐ ┌───────▼──────┐ ┌────▼──────┐   ┌───────▼───────┐
    │  vault  │ │   logger     │ │   queue   │   │   IPFS node   │
    │(secrets)│ │   service    │ │  service  │   │  (Kubo 0.39)  │
    └─────────┘ └──────────────┘ └───────────┘   └───────────────┘
                       │                │
              ┌────────▼────────┐  ┌────▼───────────────┐
              │   MongoDB :27017 │  │ topic-listener     │
              │                  │  │ service            │
              └──────────────────┘  └────────────────────┘
                       │
              ┌────────▼────────┐
              │  Redict (Redis) │
              │  cache :6379    │
              └─────────────────┘
```

### Additional Services
- **ai-service**: OpenAI-powered AI search and guided policy suggestions
- **analytics-service**: Policy analytics and reporting
- **notification-service**: Push notifications via NATS
- **application-events**: Application event processing
- **topic-listener-service**: Hedera Consensus Service topic listener
- **mrv-sender** (:3005): MRV data submission utility
- **topic-viewer** (:3006): HCS topic inspection tool

### Indexer Subsystem (separate deployment)
- **indexer-api-gateway** (:3021): NestJS REST API for the indexer
- **indexer-service**: Core indexing logic
- **indexer-worker-service**: Background indexing workers
- **indexer-frontend**: Angular UI for the indexer
- **indexer-common**: Shared library for indexer services
- **indexer-interfaces**: Shared types for indexer
- **indexer-web-proxy**: Nginx proxy for indexer UI

### Monitoring
- **Prometheus** (:9090): Metrics collection
- **Grafana** (:9080): Dashboards

---

## Workspace Packages (Yarn Workspaces)

The root `package.json` defines these workspaces (build order matters):

| Package | Path | npm Name | Purpose |
|---------|------|----------|---------|
| **interfaces** | `interfaces/` | `@guardian/interfaces` | Shared TypeScript types, enums, interfaces |
| **common** | `common/` | `@guardian/common` | Shared library: DB, Hedera modules, MQ, secrets, VC/VP/DID utils |
| **api-gateway** | `api-gateway/` | `api-gateway` | REST API layer (NestJS + Fastify) |
| **auth-service** | `auth-service/` | `auth-service` | Authentication, user management, vault integration |
| **guardian-service** | `guardian-service/` | `guardian-service` | Core business logic, schema/token/policy management |
| **policy-service** | `policy-service/` | `policy-service` | Policy Workflow Engine execution |
| **worker-service** | `worker-service/` | `worker-service` | Hedera transaction workers (IPFS, token ops) |
| **logger-service** | `logger-service/` | `logger-service` | Centralized logging (Pino → Console/Mongo/Seq) |
| **queue-service** | `queue-service/` | `queue-service` | Task queue management |
| **notification-service** | `notification-service/` | `notification-service` | Notification dispatch |
| **topic-listener-service** | `topic-listener-service/` | `topic-listener-service` | HCS topic monitoring |
| **ai-service** | `ai-service/` | `ai-service` | AI search with FAISS vectors |
| **analytics-service** | `analytics-service/` | `analytics-service` | Policy analytics |
| **mrv-sender** | `mrv-sender/` | `mrv-sender` | MRV data submission |
| **topic-viewer** | `topic-viewer/` | `topic-viewer` | HCS topic browser |
| **contracts** | `contracts/` | — | Solidity smart contracts (Hardhat + Foundry) |
| **indexer-interfaces** | `indexer-interfaces/` | — | Indexer shared types |
| **indexer-common** | `indexer-common/` | — | Indexer shared library |
| **indexer-api-gateway** | `indexer-api-gateway/` | — | Indexer REST API |
| **indexer-service** | `indexer-service/` | — | Indexer core logic |
| **indexer-worker-service** | `indexer-worker-service/` | — | Indexer background workers |

### Build Order (dependency chain)
```
interfaces → common → [all services in parallel]
```
The `interfaces` package must be built first, then `common`, then all other services can be built in any order.

---

## Key Technology Stack

### Backend Services
| Technology | Usage |
|------------|-------|
| **NestJS 11** | API gateway framework (controllers, modules, guards) |
| **Fastify** | HTTP server under NestJS in api-gateway |
| **NATS** | Inter-service message broker (pub/sub + request/reply) |
| **MikroORM 6.4** | MongoDB ORM with entity definitions |
| **MongoDB 6** | Primary database |
| **Redict 7.3** (Redis fork) | Caching layer |
| **Hiero SDK 2.78** | Hedera network interaction (formerly `@hashgraph/sdk`) |
| **Pino** | Structured logging |
| **jsonld-signatures** | W3C Verifiable Credential signing |
| **@transmute/vc.js** | VC/VP creation and verification |
| **JSZip** | Policy import/export packaging |

### Frontend
| Technology | Usage |
|------------|-------|
| **Angular 18** | Main frontend framework |
| **PrimeNG 17** | UI component library |
| **Angular Material / CDK** | Additional UI components |
| **ag-Grid 34** | Data grid / table component |
| **CodeMirror 5** | Code editor (custom logic blocks) |
| **Leader Line** | Visual connections in policy editor |
| **OpenLayers (ol)** | Map visualization |
| **SCSS** | Styling |

### Smart Contracts
| Technology | Usage |
|------------|-------|
| **Solidity** | Smart contract language |
| **Hardhat** | Development & testing framework |
| **Foundry** | Alternative testing framework |

### AI Toolkit (`hedera-guardian-ai-toolkit/`)
| Technology | Usage |
|------------|-------|
| **Python** | AI toolkit language |
| **Poetry** | Dependency management |
| **FAISS** | Vector storage for AI search |

---

## Directory Structure — Key Files

```
guardian/
├── .env                              # Root env: GUARDIAN_ENV, GUARDIAN_VERSION
├── .env.template                     # Template for root env
├── configs/
│   ├── .env.<ENV>.guardian.system     # Per-environment config (Hedera keys, IPFS, etc.)
│   ├── .env.template.guardian.system  # Template for system config
│   └── nats.conf                     # NATS broker configuration
│
├── interfaces/src/                   # @guardian/interfaces
│   ├── interface/                    # TypeScript interfaces (50+ files)
│   │   ├── policy.interface.ts
│   │   ├── schema.interface.ts
│   │   ├── vc-document.interface.ts
│   │   ├── vp-document.interface.ts
│   │   └── token.interface.ts
│   ├── type/                         # Enums and type definitions (55+ files)
│   │   ├── permissions.type.ts       # Role/permission system (large, 54KB)
│   │   ├── policy-status.type.ts
│   │   ├── block.type.ts             # All policy block types
│   │   └── user-role.type.ts
│   └── models/                       # Shared data models
│
├── common/src/                       # @guardian/common
│   ├── database-modules/
│   │   └── database-server.ts        # Central DB access layer (162KB, very large)
│   ├── entity/                       # MikroORM entity definitions (66 files)
│   │   ├── policy.ts                 # Policy entity
│   │   ├── schema.ts                 # Schema entity
│   │   ├── vc-document.ts            # Verifiable Credential entity
│   │   ├── vp-document.ts            # Verifiable Presentation entity
│   │   ├── token.ts                  # Token entity
│   │   └── did-document.ts           # DID Document entity
│   ├── hedera-modules/               # Hedera network integration
│   │   ├── vcjs/                     # VC/VP/DID creation & verification
│   │   ├── message/                  # HCS message types (34 message classes)
│   │   ├── environment.ts            # Hedera network config
│   │   └── topic-helper.ts           # HCS topic management
│   ├── mq/                           # NATS message broker abstractions
│   │   ├── message-broker-channel.ts # Core message broker class
│   │   └── nats-service.ts           # NestJS NATS integration
│   ├── secret-manager/               # Pluggable secret providers
│   │   ├── aws/                      # AWS Secrets Manager
│   │   ├── azure/                    # Azure Key Vault
│   │   ├── gcp/                      # Google Cloud Secret Manager
│   │   └── hashicorp/                # HashiCorp Vault
│   ├── import-export/                # Policy/schema import/export
│   ├── wallet/                       # Key management
│   └── integrations/                 # External service integrations
│
├── api-gateway/src/                  # REST API (NestJS controllers)
│   ├── app.ts                        # Entry point (Fastify + NATS + Swagger)
│   ├── app.module.ts                 # NestJS module (40+ controllers)
│   ├── api/service/                  # REST controllers (40 files)
│   │   ├── policy.ts                 # Policy CRUD + lifecycle (150KB, largest)
│   │   ├── schema.ts                 # Schema management (94KB)
│   │   ├── tokens.ts                 # Token operations (61KB)
│   │   ├── contract.ts               # Smart contract operations
│   │   └── account.ts                # User account management
│   ├── auth/                         # JWT auth guards
│   └── helpers/                      # Proxy helpers to microservices
│
├── guardian-service/src/             # Core business logic
│   ├── app.ts                        # Entry point (DB migration + init)
│   ├── api/                          # Message handlers (28 service files)
│   │   ├── schema.service.ts         # Schema operations (81KB)
│   │   ├── token.service.ts          # Token CRUD
│   │   ├── profile.service.ts        # User profile management
│   │   └── contract.service.ts       # Smart contract logic (125KB)
│   ├── policy-engine/                # Policy engine management
│   │   ├── policy-engine.ts          # Policy lifecycle
│   │   └── policy-engine.service.ts  # Policy message handlers
│   └── migrations/                   # MongoDB migrations (v2-4-0 through v2-28-0)
│
├── policy-service/src/               # Policy Workflow Engine
│   ├── app.ts                        # Entry point
│   ├── policy-engine/
│   │   ├── blocks/                   # 61 policy block types
│   │   │   ├── mint-block.ts         # Token minting
│   │   │   ├── request-vc-document-block.ts  # VC request forms
│   │   │   ├── documents-source.ts   # Document data sources
│   │   │   ├── calculate-block.ts    # Math calculations
│   │   │   ├── action-block.ts       # Workflow actions
│   │   │   ├── switch-block.ts       # Conditional routing
│   │   │   ├── aggregate-block.ts    # Data aggregation
│   │   │   └── ...                   # Many more block types
│   │   ├── block-tree-generator.ts   # Policy block tree construction
│   │   ├── policy-components-utils.ts # Block utilities (58KB)
│   │   ├── policy-engine.interface.ts # Engine interface (22KB)
│   │   └── mint/                     # Token minting logic
│   └── helpers/                      # Policy execution helpers
│
├── auth-service/src/                 # Authentication service
│   ├── api/                          # Auth message handlers
│   ├── vaults/                       # Vault provider implementations
│   ├── meeco/                        # Meeco identity integration
│   └── entity/                       # User entities
│
├── worker-service/src/               # Hedera transaction workers
│   ├── api/                          # Worker task handlers
│   └── helpers/                      # Transaction execution
│
├── frontend/src/                     # Angular 18 UI
│   ├── app/
│   │   ├── app.module.ts             # Root Angular module
│   │   ├── app-routing.module.ts     # Route definitions
│   │   ├── views/                    # 22 page-level components
│   │   ├── modules/
│   │   │   ├── policy-engine/        # Policy editor & viewer (largest module)
│   │   │   │   ├── policy-configuration/ # Visual policy editor
│   │   │   │   ├── policy-viewer/    # Policy execution viewer
│   │   │   │   │   └── blocks/       # Block UI renderers
│   │   │   │   ├── structures/       # Policy structure models
│   │   │   │   └── dialogs/          # Policy-related dialogs
│   │   │   ├── schema-engine/        # Schema editor
│   │   │   ├── analytics/            # Analytics module
│   │   │   └── common/               # 34+ shared UI components
│   │   ├── services/                 # 49 Angular services
│   │   │   ├── policy-engine.service.ts  # Policy API service (22KB)
│   │   │   ├── schema.service.ts     # Schema API service
│   │   │   ├── auth.service.ts       # Auth API service
│   │   │   └── web-socket.service.ts # WebSocket connection (20KB)
│   │   └── themes/                   # UI theme system
│   ├── styles.scss                   # Global styles (19KB)
│   └── variables.scss                # SCSS variables
│
├── contracts/src/                    # Solidity contracts
│   ├── retire/                       # Carbon credit retirement contracts
│   ├── wipe/                         # Token wipe contracts
│   └── access/                       # Access control contracts
│
├── docker-compose.yml                # Full demo deployment (20+ services)
├── docker-compose-quickstart.yml     # Minimal deployment
├── docker-compose-build.yml          # Build from source
├── docker-compose-production.yml     # Production (no demo)
├── docker-compose-indexer.yml        # Indexer deployment
├── docker-compose-analytics.yml      # Analytics deployment
│
├── e2e-tests/                        # Cypress E2E tests
├── load-tests/                       # JMeter load tests
├── swagger.yaml                      # OpenAPI spec (650KB)
├── swagger-indexer.yaml              # Indexer OpenAPI spec
└── Methodology Library/              # Pre-built policy methodology files (.policy)
```

---

## Service Communication Patterns

### NATS Message Broker
All backend services communicate via NATS (port 4222). The pattern uses:
- **`MessageBrokerChannel`** (from `@guardian/common`): Core abstraction for pub/sub and request/reply
- **NestJS `@nestjs/microservices`**: Controllers register as NATS listeners
- **`LargePayloadContainer`**: Handles payloads exceeding NATS limits
- **JWT Service Validation**: Each service has its own JWT keypair for inter-service auth

### Service Registration Pattern
Every service follows this startup pattern:
```typescript
Promise.all([
    DatabaseConnection,           // MikroORM init
    MessageBrokerChannel.connect('SERVICE_NAME'),  // NATS connection
    mongoForLoggingInitialization()  // Logger DB
]).then(async ([db, cn, loggerMongo]) => {
    // 1. Set up secret manager
    await new OldSecretManager().setConnection(cn).init();
    // 2. Set JWT service name
    JwtServicesValidator.setServiceName('SERVICE_NAME');
    // 3. Connect to DB
    DatabaseServer.connectBD(db);
    // 4. Register API message handlers
    await someAPI(logger);
    // 5. Update application state
    await state.updateState(ApplicationStates.READY);
});
```

### API Gateway → Microservice Proxy
The API gateway uses helper classes that proxy HTTP requests to NATS messages:
- `Guardians` → guardian-service
- `PolicyEngine` → policy-service / guardian-service
- `Users` → auth-service
- `Wallet` → auth-service
- `IPFS` → worker-service
- `AISuggestions` → ai-service
- `ProjectService` → guardian-service

---

## Core Domain Concepts

### Policies
A **Policy** is the central concept — a configurable workflow that defines how MRV data flows from submission to tokenization. Policies are composed of **blocks** (61 types available) arranged in a tree structure.

Key policy block types:
- **interfaceContainerBlock** / **interfaceStepBlock**: UI structure
- **requestVcDocumentBlock**: User form for VC submission
- **sendToGuardianBlock**: Submit documents to Guardian
- **externalDataBlock**: Receive external data
- **mintBlock**: Mint tokens
- **retirementBlock**: Retire tokens
- **calculateBlock** / **customLogicBlock**: Data processing
- **switchBlock**: Conditional routing
- **aggregateBlock**: Data collection
- **documentValidatorBlock**: Validation
- **informationBlock**: Display info

### Policy Lifecycle
```
DRAFT → DRY_RUN → PUBLISH → DISCONTINUED/DEPRECATED
```

### Schemas
JSON Schema-based document definitions. Schemas define the structure of VCs and are version-controlled with publish/deprecation lifecycle.

### Tokens
Hedera Token Service (HTS) tokens for carbon credits, renewable energy certificates, etc. Supports fungible and non-fungible tokens.

### Verifiable Credentials (VC) / Verifiable Presentations (VP)
W3C standard digital credentials. VCs are signed documents containing claims. VPs bundle VCs for presentation. All anchored to HCS topics.

### Standard Registries
Organizations that publish policies, manage schemas, and oversee verification workflows. Each registry has its own DID and Hedera account.

---

## Configuration System

### Environment Variables
Configuration follows a layered approach:
1. **Root `.env`**: `GUARDIAN_ENV` (environment name) and `GUARDIAN_VERSION`
2. **`configs/.env.<GUARDIAN_ENV>.guardian.system`**: Hedera credentials, IPFS config, JWT keys, service addresses
3. **Per-service `.env`**: Service-specific overrides (rarely needed)

### Critical Environment Variables
```bash
# Hedera Network
HEDERA_NET="testnet"          # testnet | mainnet | previewnet | localnode
OPERATOR_ID="0.0.xxxxx"      # Hedera account ID
OPERATOR_KEY="302e..."        # ED25519 private key (DER encoded)
INITIALIZATION_TOPIC_ID="..." # Root HCS topic

# Infrastructure
MQ_ADDRESS="message-broker"   # NATS server address
DB_HOST="mongo"               # MongoDB host
HOST_CACHE="cache"            # Redict/Redis host

# IPFS
IPFS_PROVIDER="web3storage"   # web3storage | filebase | local
IPFS_STORAGE_KEY="..."        # Provider-specific key
IPFS_STORAGE_PROOF="..."      # Provider-specific proof

# Auth
JWT_PRIVATE_KEY="..."         # RSA private key for JWT
JWT_PUBLIC_KEY="..."          # RSA public key for JWT
```

---

## Database

### MongoDB Collections (via MikroORM entities)
Key entities in `common/src/entity/` (66 entity files):
- `Policy`, `PolicyRoles`, `PolicyKeys`, `PolicyCache`
- `Schema`, `SchemaRule`
- `VcDocument`, `VpDocument`, `DIDDocument`
- `Token`
- `Topic`
- `Module`, `Tool`
- `Contract`, `RetirePool`, `RetireRequest`
- `Artifact`, `ArtifactChunk`
- `BlockState`, `BlockCache`
- `Record`
- `ExternalDocument`, `ExternalPolicy`
- `Formula`, `PolicyLabel`
- `Tag`, `TagCache`

### DatabaseServer
The `DatabaseServer` class (`common/src/database-modules/database-server.ts`, 162KB) is the central data access layer. It provides typed methods for CRUD operations on all entities. This is a very large file — specific methods are organized by entity type.

---

## Testing

### Unit Tests
```bash
cd guardian-service && npm run test       # Guardian service tests
cd guardian-service && npm run test:network  # Hedera network tests only
cd guardian-service && npm run test:stability # Stability tests (10x each)
cd common && npm run test                 # Common package tests
```

### E2E Tests
Located in `e2e-tests/` using **Cypress**:
```bash
cd e2e-tests && npx cypress run
```

### Load Tests
Located in `load-tests/` using **JMeter** (`.jmx` files):
- `DryFlowMintCDM.jmx` — Dry run flow for CDM methodology
- `PublishFlowMintIRec.jmx` — Publish flow for I-REC methodology

---

## Build & Run

### Docker (recommended)
```bash
# Quickstart (pre-built images, minimal services)
docker compose -f docker-compose-quickstart.yml up --pull=always -d

# Full demo (pre-built images)
docker compose up -d --build --pull always

# Build from source
docker compose -f docker-compose-build.yml up -d --build

# Production (no demo mode)
docker compose -f docker-compose-production.yml up -d --build --pull always
```

### Manual Build (development)
```bash
# Install all workspace dependencies
yarn

# Build in dependency order
yarn workspace @guardian/interfaces run build
yarn workspace @guardian/common run build

# Build services (can be parallel)
yarn workspace guardian-service run build
yarn workspace policy-service run build
yarn workspace api-gateway run build
yarn workspace auth-service run build
yarn workspace worker-service run build
yarn workspace logger-service run build
# ... other services

# Frontend
cd frontend && npm install && npm run build

# Start services
yarn workspace logger-service start
yarn workspace auth-service start
yarn workspace guardian-service start
yarn workspace policy-service start
yarn workspace worker-service start
yarn workspace api-gateway start
cd frontend && npm start  # localhost:4200
```

### PM2 (alternative)
```bash
docker-compose -f docker-compose-dev.yml up -d mongo message-broker ipfs-node
pm2 start ecosystem.config.js
```

---

## API

### REST API (api-gateway, port 3002)
- Swagger docs at `http://localhost:3002/api-docs`
- Full OpenAPI spec in `swagger.yaml` (650KB)
- API versioning via `Api-Version` header
- Auth: JWT bearer token in `Authorization` header

### Key REST Endpoints (NestJS Controllers)
| Controller | Base Path | Purpose |
|------------|-----------|---------|
| `AccountApi` | `/accounts` | User registration, login, profile |
| `PolicyApi` | `/policies` | Policy CRUD, publish, dry-run (largest: 150KB) |
| `SchemaApi` | `/schemas` | Schema management |
| `TokensApi` | `/tokens` | Token CRUD, mint, freeze/unfreeze |
| `ContractsApi` | `/contracts` | Smart contract operations |
| `ModulesApi` | `/modules` | Policy module management |
| `ToolsApi` | `/tools` | Policy tool management |
| `ProfileApi` | `/profiles` | User profile management |
| `ArtifactApi` | `/artifacts` | File artifact management |
| `TagsApi` | `/tags` | Tag system |
| `AnalyticsApi` | `/analytics` | Policy comparison/analytics |
| `FormulasApi` | `/formulas` | Formula management |
| `ExternalPoliciesApi` | `/external-policies` | Cross-instance policy sharing |

### WebSocket
WebSocket service at the api-gateway provides real-time updates for:
- Policy execution progress
- Task completion notifications
- Block state changes

---

## Frontend Architecture (Angular 18)

### Module Organization
| Module | Path | Purpose |
|--------|------|---------|
| **policy-engine** | `modules/policy-engine/` | Largest module — policy editor, viewer, blocks |
| **schema-engine** | `modules/schema-engine/` | Schema editor and viewer |
| **analytics** | `modules/analytics/` | Comparison and analytics views |
| **common** | `modules/common/` | 34+ shared components |
| **formulas** | `modules/formulas/` | Formula editor |
| **statistics** | `modules/statistics/` | Policy statistics |
| **contract-engine** | `modules/contract-engine/` | Smart contract UI |

### Key Views (page components)
Located in `frontend/src/app/views/`:
- `admin/` — Admin panel
- `login/` — Authentication
- `schemas/` — Schema management
- `token-config/` — Token configuration
- `trust-chain/` — Trust chain viewer
- `policy-search/` — Policy search
- `user-profile/` — User profile
- `roles/` — Role management

### Services (Angular DI)
49 services in `frontend/src/app/services/` including:
- `PolicyEngineService` (22KB) — Policy API calls
- `SchemaService` — Schema API calls
- `AuthService` — Authentication
- `WebSocketService` (20KB) — Real-time updates
- `TokenService` — Token operations
- `BrandingService` — White-label configuration

### UI Libraries
- **PrimeNG** for most UI components (dialogs, tables, dropdowns, etc.)
- **Angular Material** for specific components
- **ag-Grid** for complex data tables
- **CodeMirror** for code editing in custom logic blocks

---

## Smart Contracts (Solidity)

Located in `contracts/src/`:
- **`retire/`** — Carbon credit retirement contracts (with file IDs for testnet)
- **`wipe/`** — Token wipe contracts
- **`access/`** — Access control contracts
- **`hts-precompile/`** — Hedera Token Service precompile wrappers

Build with: `cd contracts && npx hardhat compile`

---

## Common Patterns & Conventions

### Adding a New Service API
1. Create message handler in `guardian-service/src/api/your-feature.service.ts`
2. Register it in `guardian-service/src/app.ts`
3. Create proxy helper in `api-gateway/src/helpers/your-feature.ts`
4. Create NestJS controller in `api-gateway/src/api/service/your-feature.ts`
5. Register controller in `api-gateway/src/app.module.ts`
6. Add frontend service in `frontend/src/app/services/your-feature.service.ts`

### Entity Definition Pattern
Entities use MikroORM decorators in `common/src/entity/`:
```typescript
@Entity()
export class MyEntity extends BaseEntity {
    @Property() name: string;
    @Property() status: string;
    @Property() owner: string;
    // ...
}
```

### Message Handler Pattern
Services register NATS message handlers:
```typescript
export async function myFeatureAPI(logger: PinoLogger) {
    ApiResponse(MessageAPI.MY_FEATURE_ACTION, async (msg) => {
        // Handle message
        return new MessageResponse(result);
    });
}
```

### Policy Block Pattern
New policy blocks inherit from base classes in `policy-service/src/policy-engine/`:
```typescript
@BlockValidator({
    blockType: 'myBlockType',
    // ...
})
export class MyBlock {
    // Block logic
}
```

---

## Key Files to Understand First

When onboarding, read these files in order:
1. `interfaces/src/type/block.type.ts` — All policy block types
2. `interfaces/src/type/permissions.type.ts` — Permission system
3. `common/src/entity/policy.ts` — Policy entity structure
4. `common/src/database-modules/database-server.ts` — Data access (browse, don't read all 162KB)
5. `common/src/mq/message-broker-channel.ts` — Inter-service communication
6. `api-gateway/src/app.module.ts` — All REST endpoints
7. `guardian-service/src/app.ts` — Core service initialization
8. `policy-service/src/policy-engine/blocks/index.ts` — All block registrations

---

## Common Gotchas

1. **Build order matters**: Always build `interfaces` → `common` before any service
2. **ES Modules**: All packages use `"type": "module"` — imports must use `.js` extensions
3. **Large files**: `database-server.ts` (162KB), `policy.ts` controller (150KB), `permissions.type.ts` (54KB) — these are intentionally monolithic
4. **NATS payload limits**: Default 1MB (`MQ_MAX_PAYLOAD`). `LargePayloadContainer` handles overflow
5. **Hedera costs**: Mainnet operations cost HBAR. Always develop on testnet
6. **Frontend proxy**: Dev server proxies `/api` to `localhost:3002` (see `proxy.conf.json`)
7. **Docker networking**: Services reference each other by Docker service names (e.g., `mongo`, `message-broker`)
8. **Migration system**: Guardian service runs migrations on startup — check `guardian-service/src/migrations/`
9. **Dual build configs**: Each service has `tsconfig.json` (dev) and `tsconfig.production.json` (prod) — Gulp tasks select between them
10. **Frontend is NOT in Yarn workspaces**: The Angular frontend has its own `package-lock.json` and uses `npm`, not yarn

---

## External Integrations

- **Hedera Network**: HCS (topics/messages), HTS (tokens), accounts — via `@hiero-ledger/sdk`
- **IPFS**: Document storage — via Storacha (web3storage), Filebase, or local Kubo node
- **HashiCorp Vault**: Secure key storage (optional)
- **AWS/Azure/GCP Secret Managers**: Cloud secret storage (optional)
- **Meeco**: Identity verification integration (optional)
- **OpenAI**: AI-powered policy search and suggestions

---

## Excluded from Guardian Architecture

The following directories are **NOT** part of the Guardian codebase proper:

| Directory | Description |
|-----------|-------------|
| `sustainable-explorer/` | **Separate project** — Sustainability Explorer (Nuxt 3 + Vue 3 frontend). Has its own architecture, tech stack, and Claude agent definition at `.claude/agents/frontend-dev.md` |
| `hedera-guardian-ai-toolkit/` | Standalone Python AI toolkit (uses Poetry, FAISS). Can be deployed independently |
| `demia/` | Demia integration documentation and test scripts |
| `Methodology Library/` | Pre-built `.policy` files for import — not source code |
| `grafana/` | Grafana dashboard configs (JSON) |
| `vault/` | HashiCorp Vault setup scripts |
| `k8s-manifests/` | Kubernetes deployment manifests |

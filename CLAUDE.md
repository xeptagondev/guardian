# CLAUDE.md - Guardian Project Guide

## What is Guardian?

Guardian is an open-source platform built on the Hedera network that streamlines the creation, management, and verification of digital environmental assets. It integrates a customizable Policy Workflow Engine with Web3 technology (DIDs, Verifiable Credentials) for transparent, fraud-proof sustainability and carbon market operations.

## Repository Structure

This is a **monorepo** using **Yarn 1.22 workspaces**. All services are TypeScript/Node.js 20 with NestJS.

### Core Services
- `api-gateway/` - Main REST API entry point (port 3002)
- `guardian-service/` - Core business logic, Hedera network interaction
- `policy-service/` - Policy workflow execution engine
- `auth-service/` - Authentication (JWT with RSA 2048-bit keys, port 6555)
- `worker-service/` - Background task processing
- `queue-service/` - Message queue management
- `logger-service/` - Centralized logging
- `notification-service/` - Notification delivery
- `analytics-service/` - Data aggregation and reporting
- `ai-service/` - LLM integration via LangChain/OpenAI (port 3013)
- `topic-listener-service/` - Hedera topic monitoring
- `application-events/` - Event streaming (port 3012)

### Shared Libraries
- `interfaces/` - Shared type definitions (build first)
- `common/` - Shared utilities (build second)

### Frontend
- `frontend/` - Angular 18 app with PrimeNG, AG Grid, OpenLayers (port 4200 dev / 3000 prod)

### Other
- `contracts/` - Solidity smart contracts (Hardhat + Foundry)
- `indexer-*/` - Blockchain indexing services (separate subsystem)
- `mrv-sender/` - MRV data submission (port 3005)
- `topic-viewer/`, `tree-viewer/` - Visualization tools
- `guardian-cli/` - CLI management tool
- `e2e-tests/` - Cypress E2E tests
- `configs/` - Environment configuration templates
- `vault/` - HashiCorp Vault integration
- `docs/` - Documentation

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | TypeScript, NestJS 11, Node.js 20.19.5 |
| Frontend | Angular 18, PrimeNG 17, AG Grid 34 |
| Database | MongoDB 6 (via MikroORM 6.4) |
| Message Broker | NATS 2.9.25 |
| Cache | Redict 7.3.6 (Redis fork) |
| Blockchain | Hedera/Hiero SDK 2.78.0, ethers.js 6 |
| AI/ML | LangChain 1.0, FAISS, OpenAI |
| Smart Contracts | Solidity 0.8.11, Hardhat, Foundry |
| Secrets | HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager |
| Monitoring | Prometheus, Grafana |

## Build & Run

### Prerequisites
- Node.js v20.19.5, Yarn 1.22, Docker Desktop > 3.6.0
- MongoDB v6, NATS, Redict
- Hedera testnet/mainnet account with ED25519 keys in DER format
- IPFS provider account (Storacha/Filebase) or local Kubo node

### Build Order (shared libraries must be built first)
```bash
yarn                                          # Install all dependencies
yarn workspace @guardian/interfaces run build  # 1. Build interfaces
yarn workspace @guardian/common run build      # 2. Build common
# Then build individual services as needed
```

### Docker (recommended)
```bash
# Configure .env from .env.template with OPERATOR_ID, OPERATOR_KEY, HEDERA_NET, etc.
docker-compose up -d --build                  # Full development stack
```

### Docker Compose Variants
- `docker-compose.yml` - Full development stack
- `docker-compose-production.yml` - Production deployment
- `docker-compose-quickstart.yml` - Minimal quick start
- `docker-compose-indexer.yml` - Indexer services only
- `docker-compose-analytics.yml` - Analytics services only

### Manual Service Start Order
1. Logger Service
2. Auth Service
3. Policy Service
4. Worker Service
5. Notification Service
6. Guardian Service
7. API Gateway
8. AI Service (optional)
9. MRV Sender
10. Frontend

## Testing

### Unit Tests (Mocha/Chai)
```bash
cd <service-dir> && npm run test              # Run service unit tests
npm run test:local                            # Local test variant
npm run test:network                          # Hedera network tests (guardian-service)
npm run test:stability                        # Stress tests (guardian-service)
```
Test results output as JUnit XML in `test_results/`.

### E2E Tests (Cypress)
```bash
cd e2e-tests
npm run ui-only                               # Frontend UI tests
npm run api-tests                             # API tests
npm run smoke-pull                            # Smoke tests
```

### Frontend Tests
```bash
cd frontend && ng test                        # Karma/Jasmine tests
```

### Policy Testing (Built-in Platform Features)
- **Dry Run** - Execute policies without blockchain transactions
- **Savepoints** - Checkpoint/restore during dry run
- **Record/Replay** - Capture and replay policy execution for regression testing

## Code Style

- **Linter:** TSLint (`tslint.json` at root)
- **Max line length:** 360 characters
- **Quotes:** Single quotes
- **File naming:** kebab-case
- **Module system:** ES modules (`"type": "module"`)
- **Indentation:** 4 spaces
- **Line endings:** LF
- **Prefer:** `const`, arrow functions, strict equality (`===`)
- **No:** `var` keyword, `console` in production

## Environment Configuration

### Key Environment Variables
- `GUARDIAN_ENV` - Environment identifier
- `HEDERA_NET` - Network target (testnet/mainnet/localnode)
- `OPERATOR_ID` / `OPERATOR_KEY` - Hedera operator credentials (ED25519 DER)
- `DB_HOST` / `DB_DATABASE` - MongoDB connection
- `MQ_ADDRESS` - NATS message queue address
- `IPFS_PROVIDER` - Storage backend (local/web3storage/filebase)
- `LOG_LEVEL` - Logging verbosity
- `SEND_KEYS_TO_VAULT` - Toggle vault key management

### Config Templates
- `.env.template` (root) - Main environment template
- `configs/.env.develop.guardian.system` - Development config
- `configs/.env.quickstart.guardian.system` - Quick start config

## CI/CD

GitHub Actions workflows in `.github/workflows/`:
- `main.yml` - Primary CI (build all services, lint, secret detection) on push to main
- `publish.yml` - Docker image publishing to GCR (multi-platform: amd64/arm64)
- `api-manual.yml`, `ui-manual.yml` - Manual test triggers
- `flow-pull-request-formatting.yaml` - PR format checks

## API Documentation

- `swagger.yaml` - Main API docs (700+ endpoints)
- `swagger-analytics.yaml` - Analytics API
- `swagger-indexer.yaml` - Indexer API
- Full docs: https://dev.guardian.hedera.com/

## Key Concepts

- **Standard Registry** - Admin role managing schemas and policies
- **Policy Workflow** - Series of deterministic policy actions connected causally
- **Policy Action/Block** - Deterministic rules producing state transitions (50+ block types)
- **DID** - Decentralized Identifier (W3C standard)
- **VC/VP** - Verifiable Credential / Verifiable Presentation
- **MRV** - Measurement, Reporting, Verification
- **Dry Run** - Test policy execution without blockchain transactions
- **Modules** - Reusable policy components
- **Tools** - Shared utilities across policies

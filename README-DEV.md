# Guardian — Local Development Guide

This guide covers running all Guardian services locally with hot-reload, using Docker only for infrastructure (MongoDB + NATS + IPFS).

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Node.js | v20 LTS | **Must be v20** — v22+ breaks `@transmute/jsonld` (esm shim incompatibility). Use [nvm](https://github.com/nvm-sh/nvm) or [fnm](https://github.com/Schniz/fnm). An `.nvmrc` is included: run `nvm use`. |
| Yarn | v1.22+ | This repo uses Yarn classic (`packageManager: yarn@1.22.21`) |
| Docker | v24+ | Docker Desktop or Docker Engine |
| Docker Compose | V2 (`docker compose`) | Bundled with Docker Desktop v4+ |

---

## Environment Setup

Before starting any services, copy the dev environment example and fill in your credentials:

```bash
cp .env.dev.example .env.dev
```

Then open `.env.dev` and fill in the values marked with `<...>`:

| Variable | Where to get it |
|---|---|
| `OPERATOR_ID` | [Hedera Developer Portal](https://portal.hedera.com) — your testnet Account ID |
| `OPERATOR_KEY` | Hedera Developer Portal — DER Encoded Private Key |
| `JWT_PRIVATE_KEY` | Generate: `openssl genrsa 2048` — paste full PEM as single line with `\n` |
| `JWT_PUBLIC_KEY` | Derived from the private key: `openssl rsa -pubout` |
| `SERVICE_JWT_SECRET_KEY_ALL` | Generate: `openssl rand -hex 64` |
| `SR_INITIAL_PASSWORD` | Any password — used for the first Standard Registry account |

> **Note:** `IPFS_PROVIDER` defaults to `local` — the IPFS Kubo node runs in Docker and needs no account or API key. All other variables have working defaults for local dev. You only need the 6 values above.

---

## Quick Start

### 1. Clone and install dependencies

```bash
git clone https://github.com/hashgraph/guardian.git
cd guardian
yarn install
```

### 2. Set up environment

```bash
cp .env.dev.example .env.dev
# Edit .env.dev and fill in OPERATOR_ID, OPERATOR_KEY,
# JWT_PRIVATE_KEY, JWT_PUBLIC_KEY, SERVICE_JWT_SECRET_KEY_ALL,
# and SR_INITIAL_PASSWORD
```

### 3. Start infrastructure

```bash
yarn dev:infra
```

Starts MongoDB (27017), NATS (4222), IPFS Kubo (5001 / 8080), and Mongo Express (8081) in Docker.

Wait for MongoDB to be healthy: `docker compose -f docker-compose-dev.yml ps`

> **Tip:** `yarn dev:backend:run` loads `.env.dev` automatically via `dotenv-cli` — no manual sourcing needed on any platform.

### 4. Build shared packages (first time only)

The backend services depend on `@guardian/interfaces` and `@guardian/common`. These must be compiled before services can start. `yarn dev:backend` does this automatically, but you can also run it manually:

```bash
yarn dev:deps
```

This builds `interfaces` → `common` in order (takes ~10–20 s). On subsequent runs the compiled `dist/` folders already exist, so this step is very fast.

### 5. Start backend services

```bash
yarn dev:backend
```

This builds shared packages first, then starts TypeScript watch compilers for all 7 core backend services. Each service output is labeled and color-coded.

> **Two-process model:** Each Guardian service needs two concurrent processes:
>
> 1. **Compiler** (`yarn dev:backend`) — watches `.ts` files and recompiles to `dist/`
> 2. **Runner** (`yarn dev:backend:run`) — loads `.env.dev` automatically via `dotenv-cli`, then starts `nodemon` for each service
>
> Wait for the first compiler pass to finish (watch for "Found 0 errors"), then in a second terminal:
>
> ```bash
> # Terminal 1 — compilers
> yarn dev:backend
>
> # Terminal 2 — runners (after Terminal 1 shows "Found 0 errors")
> yarn dev:backend:run
> ```
>
> `.env.dev` is loaded automatically by `dev:backend:run` — no shell sourcing required (works on Windows PowerShell, bash, and zsh).

### 6. Start the frontend

```bash
yarn dev:frontend
```

Installs frontend dependencies (first run only), then starts the Angular dev server at **http://localhost:4200** with proxy to the API gateway.

### One-liner (infra + everything)

```bash
yarn dev:all
```

---

## Available Commands

| Command | Description |
|---------|-------------|
| `yarn dev:infra` | Start MongoDB, NATS, IPFS, and Mongo Express in Docker (detached) |
| `yarn dev:infra:down` | Stop and remove dev infrastructure containers |
| `yarn dev:infra:logs` | Tail logs from all infrastructure containers |
| `yarn dev:deps` | Build shared packages (`interfaces` → `common`) — run once before first `dev:backend` |
| `yarn dev:backend` | Build shared packages, then start TypeScript watch compilers for all 7 backend services |
| `yarn dev:backend:run` | Start the Node.js runners (nodemon) for all 7 backend services — run after `dev:backend` has compiled |
| `yarn dev:frontend` | Install frontend deps (if needed) and start Angular at http://localhost:4200 |
| `yarn dev:indexer` | Start the Hedera indexer service TypeScript compiler (optional) |
| `yarn dev` | `dev:backend` + `dev:frontend` together (no infra) |
| `yarn dev:all` | Start infra, then `dev:backend` + `dev:frontend` |

---

## Service Port Reference

| Service | Default Port | Notes |
|---------|-------------|-------|
| `api-gateway` | 3002 | REST API — primary backend entry point |
| `auth-service` | 6555 (internal) | Authentication; communicates over NATS |
| `guardian-service` | 6555 (internal) | Policy workflow engine |
| `policy-service` | 5006 (internal) | Policy execution |
| `worker-service` | 6555 (internal) | Background tasks (IPFS, Hedera) |
| `notification-service` | — | WebSocket events over NATS |
| `logger-service` | 6555 (internal) | Centralized log aggregation |
| `frontend` | 4200 | Angular dev server |
| MongoDB | 27017 | Dev container (`dev-mongo`) |
| NATS | 4222 / 8222 | 4222 = client, 8222 = HTTP monitoring UI |
| IPFS Kubo | 5001 / 8080 | 5001 = API (`IPFS_NODE_ADDRESS`), 8080 = gateway |
| Redict (cache) | 6379 | Redis-compatible cache — dev container (`dev-cache`) |
| Mongo Express | 8081 | Web UI for MongoDB (`admin` / `pass`) |

---

## How Services Load Environment Variables

Each service loads configuration in this priority order (highest first):

1. **Shell environment** — variables exported before the process starts (e.g., from `.env.dev`)
2. **Service root `.env`** — `<service-dir>/.env` (loaded via `dotenv.config()`)
3. **Service config file** — `<service-dir>/configs/.env.<service>[.<GUARDIAN_ENV>]`

Because `dotenv` does **not** override already-set variables by default, sourcing `.env.dev` into your shell gives those values the highest priority and overrides the defaults in the service config files.

The actual database name used is:
- `<GUARDIAN_ENV>_<HEDERA_NET>_<DB_DATABASE>` when `GUARDIAN_ENV` is set
- Just `<DB_DATABASE>` when `GUARDIAN_ENV` is blank (recommended for local dev)

---

## Optional Services

These services are not started by `yarn dev:backend`. Start them individually if needed:

```bash
# Hedera topic indexer (separate stack)
yarn dev:indexer

# AI features service
yarn workspace ai-service dev

# Analytics service
yarn workspace analytics-service dev

# MRV sender (demo only)
yarn workspace mrv-sender dev
```

---

## Vault Setup (Skipped in Dev)

By default the auth-service uses `VAULT_PROVIDER=database`, which stores keys in MongoDB. HashiCorp Vault is **not required** for local development.

To use Vault, set `VAULT_PROVIDER=hashicorp` in your `.env.dev`, then start Vault separately:

```bash
docker run --cap-add=IPC_LOCK \
  -e VAULT_DEV_ROOT_TOKEN_ID=hVt34rnXcHnxp520LHYK \
  -p 8200:8200 hashicorp/vault:1.12.11
```

---

## Troubleshooting

**`ioredis ECONNREFUSED` on port 6379** — the cache container isn't running. Run `yarn dev:infra` (the `dev-cache` Redict container exposes port 6379).

**`secretOrPrivateKey must have a value`** — `SERVICE_JWT_SECRET_KEY_ALL` is empty or still a placeholder in `.env.dev`. Generate a value: `openssl rand -hex 64`, paste into `.env.dev` for both `SERVICE_JWT_SECRET_KEY_ALL` and `SERVICE_JWT_PUBLIC_KEY_ALL`. Restart `yarn dev:backend:run`.

**`TypeError: Function.prototype.apply was called on undefined` / `esm.js` crash** — you are running Node.js v22 or v24. The `esm` shim used by `@transmute/jsonld` is broken on anything above v20. Switch to Node.js v20 LTS: `nvm use` (the repo includes `.nvmrc`).

**`Cannot find module '@guardian/common'`** — shared packages haven't been built. Run `yarn dev:deps` (or just `yarn dev:backend`, which does it automatically).

**MongoDB connection refused** — wait for the healthcheck: `docker compose -f docker-compose-dev.yml ps`

**NATS connection refused** — check the container: `docker compose -f docker-compose-dev.yml logs nats`

**IPFS upload failures** — check the Kubo container: `docker compose -f docker-compose-dev.yml logs ipfs-node`. Confirm `IPFS_NODE_ADDRESS=http://localhost:5001` and `IPFS_PROVIDER=local` are set.

**Services start but immediately exit** — check that `.env.dev` is sourced and `OPERATOR_ID`, `OPERATOR_KEY`, `MQ_ADDRESS`, and `DB_HOST` are set.

**Frontend `ng` not found** — `yarn dev:frontend` runs `yarn install` in the frontend folder automatically on first run. If it still fails, run `cd frontend && yarn install` manually.

**Frontend proxy errors** — ensure `api-gateway` is running on port 3002 before starting the frontend. Check `frontend/proxy.conf.json` for the target URL.

**Port already in use** — check for stale processes: `lsof -i :3002` (Linux/Mac) or `netstat -ano | findstr :3002` (Windows).

**Database name looks wrong** — if `GUARDIAN_ENV` is set, the DB name is prefixed (e.g., `develop_testnet_guardian_db`). Set `GUARDIAN_ENV=` (empty) in `.env.dev` to use plain names like `guardian_db`.

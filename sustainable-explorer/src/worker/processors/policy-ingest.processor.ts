import { Processor, WorkerHost, OnWorkerEvent, InjectQueue } from '@nestjs/bullmq';
import { Inject, Logger } from '@nestjs/common';
import { Job, Queue } from 'bullmq';
import { DataSource } from 'typeorm';
import Redis from 'ioredis';
import AdmZip from 'adm-zip';
import { QUEUE_NAMES } from '@shared/config/bullmq.config';
import { IpfsService } from '../services/ipfs.service';

export interface PolicyIngestJobData {
    cid: string;
    messageTimestamp: string;
    policyTopicId: string;
    instanceTopicId: string;
    owner: string | null;
    policyName: string | null;
    policyVersion: string | null;
    policyUuid: string | null;
}

interface ExtractedSchema {
    iri: string;
    uuid: string;
    version: string;
    name: string | null;
    description: string | null;
    entity: string | null;
    topicId: string | null;
    properties: string[];
    role: string;
}

interface ExtractedToken {
    tokenName: string | null;
    tokenSymbol: string | null;
    tokenType: string | null;
    decimals: number | null;
}

@Processor(QUEUE_NAMES.POLICY_INGEST)
export class PolicyIngestProcessor extends WorkerHost {
    private readonly logger = new Logger(PolicyIngestProcessor.name);

    constructor(
        private readonly ipfsService: IpfsService,
        private readonly dataSource: DataSource,
        @Inject('REDICT_PUB') private readonly redis: Redis,
        @InjectQueue(QUEUE_NAMES.TOPIC_SYNC) private readonly topicQueue: Queue,
        @InjectQueue(QUEUE_NAMES.POLICY_INGEST) private readonly policyIngestQueue: Queue,
        @InjectQueue(QUEUE_NAMES.PROJECT_EXTRACT) private readonly projectExtractQueue: Queue,
    ) {
        super();
    }

    async process(job: Job<PolicyIngestJobData>): Promise<void> {
        // Handle repeatable maintenance jobs (retry-stopped) separately
        if (job.name === 'retry-stopped') {
            await this.retryStoppedPolicies();
            return;
        }

        const { cid, messageTimestamp, policyTopicId, instanceTopicId, owner } = job.data;

        if (!cid || !instanceTopicId) {
            this.logger.warn(`Skipping policy ingest job with missing data: cid=${cid}, instanceTopicId=${instanceTopicId}`);
            return;
        }

        this.logger.log(`Ingesting policy ZIP for ${instanceTopicId} (CID: ${cid})`);

        // Idempotency: skip if already decoded
        const existing = await this.dataSource.query(
            `SELECT status FROM policy WHERE "instanceTopicId" = $1 LIMIT 1`,
            [instanceTopicId],
        );
        if (existing.length > 0 && existing[0].status === 'DECODED') {
            this.logger.log(`Policy for ${instanceTopicId} already decoded, skipping`);
            await this.unblockChildTopics(instanceTopicId);
            return;
        }

        // Upsert policy row as PENDING
        await this.dataSource.query(
            `INSERT INTO policy (
                "instanceTopicId", "policyTopicId", "messageTimestamp", cid, owner, status, "retryCount",
                "createdAt", "updatedAt"
            ) VALUES ($1, $2, $3, $4, $5, 'PENDING', 0, NOW(), NOW())
            ON CONFLICT ("instanceTopicId") DO UPDATE SET
                "retryCount" = policy."retryCount" + 1,
                status = 'PENDING',
                "failReason" = NULL,
                "updatedAt" = NOW()`,
            [instanceTopicId, policyTopicId, messageTimestamp, cid, owner],
        );

        // Download ZIP from IPFS
        const content = await this.ipfsService.fetchContent(cid);

        // Cache raw bytes in ipfs_files
        await this.dataSource.query(
            `INSERT INTO ipfs_files (cid, content, size, "createdAt")
             VALUES ($1, $2, $3, NOW())
             ON CONFLICT (cid) DO NOTHING`,
            [cid, content, content.length],
        );

        // Verify ZIP magic (PK\x03\x04)
        if (content.length < 4 || content[0] !== 0x50 || content[1] !== 0x4B) {
            const reason = `CID ${cid} is not a valid ZIP archive (${content.length} bytes, magic: ${content.slice(0, 4).toString('hex')})`;
            await this.markFailed(instanceTopicId, reason);
            throw new Error(reason);
        }

        // Extract ZIP
        const zip = new AdmZip(content);
        const entries = zip.getEntries();

        // Parse policy.json
        const policyEntry = entries.find(e => e.entryName === 'policy.json');
        if (!policyEntry) {
            const reason = `ZIP for CID ${cid} does not contain policy.json`;
            await this.markFailed(instanceTopicId, reason);
            throw new Error(reason);
        }

        let policyJson: Record<string, unknown>;
        try {
            policyJson = JSON.parse(policyEntry.getData().toString('utf-8'));
        } catch {
            const reason = `Failed to parse policy.json from CID ${cid}`;
            await this.markFailed(instanceTopicId, reason);
            throw new Error(reason);
        }

        // Extract schemas
        const schemas = this.extractSchemas(entries);

        // Extract tokens
        const tokens = this.extractTokens(entries);

        // Extract metadata from policy.json
        const name = (policyJson.name as string) || job.data.policyName || null;
        const version = (policyJson.version as string) || job.data.policyVersion || null;
        const uuid = (policyJson.uuid as string) || job.data.policyUuid || null;

        // Save decoded policy
        await this.dataSource.query(
            `UPDATE policy SET
                name = $2,
                version = $3,
                uuid = $4,
                "policyJson" = $5,
                schemas = $6,
                tokens = $7,
                status = 'DECODED',
                "failReason" = NULL,
                "updatedAt" = NOW()
            WHERE "instanceTopicId" = $1`,
            [
                instanceTopicId,
                name,
                version,
                uuid,
                JSON.stringify(policyJson),
                JSON.stringify(schemas),
                JSON.stringify(tokens),
            ],
        );

        // Update the Instance-Policy message's documents with parsed policy.json
        await this.dataSource.query(
            `UPDATE message SET documents = $1 WHERE "consensusTimestamp" = $2`,
            [JSON.stringify(policyJson), messageTimestamp],
        );

        // Unblock STOPPED child topics
        await this.unblockChildTopics(instanceTopicId);

        // Enqueue project-schema resolution for this policy. The processor
        // is idempotent so re-runs are cheap, and the trigger here keeps
        // us responsive — we don't have to wait for the next maintenance sweep.
        await this.projectExtractQueue.add('resolve-one', { instanceTopicId }, {
            jobId: `project-resolve-${instanceTopicId}-${Date.now()}`,
        });

        await this.redis.publish('se:events', JSON.stringify({
            type: 'policy-decoded',
            instanceTopicId,
            name,
            cid,
            schemaCount: schemas.length,
            tokenCount: tokens.length,
            timestamp: new Date().toISOString(),
        }));

        this.logger.log(
            `Policy decoded: ${name} (${instanceTopicId}) — ${schemas.length} schemas, ${tokens.length} tokens`,
        );
    }

    /**
     * Periodic maintenance: finds FAILED policies and re-enqueues ingest jobs.
     * Also finds Instance-Policy messages that have no policy row yet.
     */
    private async retryStoppedPolicies(): Promise<void> {
        // Re-enqueue FAILED policies
        const failed: { instanceTopicId: string; policyTopicId: string; messageTimestamp: string; cid: string; owner: string | null; name: string | null }[] =
            await this.dataSource.query(
                `SELECT "instanceTopicId", "policyTopicId", "messageTimestamp", cid, owner, name
                 FROM policy WHERE status = 'FAILED' AND "retryCount" < 10`,
            );

        for (const p of failed) {
            await this.policyIngestQueue.add('ingest', {
                cid: p.cid,
                messageTimestamp: p.messageTimestamp,
                policyTopicId: p.policyTopicId,
                instanceTopicId: p.instanceTopicId,
                owner: p.owner,
                policyName: p.name,
                policyVersion: null,
                policyUuid: null,
            }, {
                jobId: `policy-ingest-retry-${p.cid}-${Date.now()}`,
            });
        }

        // Find Instance-Policy messages with no policy row (missed during initial processing)
        const orphans: { consensusTimestamp: string; topicId: string; owner: string | null; files: string[] | null; options: Record<string, unknown> | null }[] =
            await this.dataSource.query(
                `SELECT m."consensusTimestamp", m."topicId", m.owner, m.files, m.options
                 FROM message m
                 LEFT JOIN policy p ON p."messageTimestamp" = m."consensusTimestamp"
                 WHERE m.type = 'Instance-Policy' AND m.action = 'publish-policy'
                   AND m.files IS NOT NULL
                   AND p.id IS NULL
                 LIMIT 50`,
            );

        for (const o of orphans) {
            if (!o.files || o.files.length === 0) continue;
            const opts = o.options || {};
            await this.policyIngestQueue.add('ingest', {
                cid: o.files[0],
                messageTimestamp: o.consensusTimestamp,
                policyTopicId: o.topicId,
                instanceTopicId: (opts.topicId as string) || (opts.instanceTopicId as string) || o.topicId,
                owner: o.owner,
                policyName: (opts.name as string) || null,
                policyVersion: (opts.version as string) || null,
                policyUuid: (opts.uuid as string) || null,
            }, {
                jobId: `policy-ingest-orphan-${o.files[0]}-${Date.now()}`,
            });
        }

        if (failed.length > 0 || orphans.length > 0) {
            this.logger.log(`Policy retry: ${failed.length} failed re-enqueued, ${orphans.length} orphans enqueued`);
        }
    }

    /**
     * Sets STOPPED child topics to NEW and enqueues TOPIC_SYNC jobs for them.
     * Uses atomic UPDATE ... RETURNING to avoid race conditions with other workers.
     */
    private async unblockChildTopics(instanceTopicId: string): Promise<void> {
        const unblocked: { topicId: string }[] = await this.dataSource.query(
            `UPDATE topic_cache SET status = 'NEW', "lastUpdate" = $2
             WHERE "policyTopicId" = $1 AND status = 'STOPPED'
             RETURNING "topicId"`,
            [instanceTopicId, Date.now()],
        );

        for (const row of unblocked) {
            await this.topicQueue.add('sync', {
                topicId: row.topicId,
                fromSequenceNumber: 0,
                isOrgTopic: false,
            }, {
                jobId: `topic-${row.topicId}-unblocked-${Date.now()}`,
            });
        }

        if (unblocked.length > 0) {
            this.logger.log(`Unblocked ${unblocked.length} child topics for ${instanceTopicId}`);
        }
    }

    private async markFailed(instanceTopicId: string, reason: string): Promise<void> {
        await this.dataSource.query(
            `UPDATE policy SET status = 'FAILED', "failReason" = $2, "updatedAt" = NOW()
             WHERE "instanceTopicId" = $1`,
            [instanceTopicId, reason],
        );
    }

    /**
     * Extracts schema definitions from ZIP entries under schemas/.
     * Each schema file is a Guardian Schema entity with a nested document
     * containing a JSON-Schema whose properties are the VC field names.
     */
    private extractSchemas(entries: AdmZip.IZipEntry[]): ExtractedSchema[] {
        const schemas: ExtractedSchema[] = [];

        for (const entry of entries) {
            if (!entry.entryName.startsWith('schemas/') || entry.isDirectory) continue;

            try {
                const json = JSON.parse(entry.getData().toString('utf-8'));
                const iri = (json.iri as string) || entry.entryName;
                const match = iri.match(/^#?([0-9a-f-]+)&(.+)$/i);

                const properties = this.extractPropertyNames(json.document);
                const role = this.classifySchemaRole(properties, json.name);

                schemas.push({
                    iri,
                    uuid: match?.[1] || iri,
                    version: match?.[2] || '1.0.0',
                    name: json.name || json.title || null,
                    description: json.description || null,
                    entity: json.entity || null,
                    topicId: json.topicId || null,
                    properties,
                    role,
                });
            } catch {
                this.logger.warn(`Failed to parse schema file: ${entry.entryName}`);
            }
        }

        return schemas;
    }

    /**
     * Extracts top-level property names from a JSON-Schema document.
     */
    private extractPropertyNames(doc: Record<string, unknown> | undefined): string[] {
        if (!doc) return [];
        const props = doc.properties as Record<string, unknown> | undefined;
        if (!props) return [];
        return Object.keys(props).filter(k => !k.startsWith('@'));
    }

    /**
     * Classifies a schema's role by inspecting its property names and title.
     * This heuristic determines how VCs using this schema should be treated.
     */
    private classifySchemaRole(properties: string[], name: string | null): string {
        const nameLC = (name || '').toLowerCase();
        const propSet = new Set(properties.map(p => p.toLowerCase()));

        const has = (...fields: string[]) => fields.every(f => propSet.has(f));
        const hasAny = (...fields: string[]) => fields.some(f => propSet.has(f));

        // Mint / tokenization
        if (nameLC.includes('mint') || has('quantity', 'hedera_token_id')) return 'TOKENIZATION';
        if (has('tokenid', 'amount')) return 'MINT';

        // Project definition
        if (has('project_id', 'site_name')) return 'SITE';
        if (hasAny('projectdescription', 'project_description') || nameLC.includes('project data')) return 'PROJECT_INFO';

        // Issuance
        if (has('total_issuance', 'vintage') || nameLC.includes('issuance')) return 'ISSUANCE';

        // MRV / monitoring
        if (hasAny('carbonremovals', 'totalnetremoval', 'totalGrossRemoval')) return 'MRV';
        if (nameLC.includes('monitoring') || has('monitoring_period_start_date')) return 'MONITORING';

        // Registry
        if (nameLC.includes('standard registry') || nameLC === 'standardregistry') return 'REGISTRY';

        // Location
        if (has('country', 'region') || has('country', 'state_province')) return 'LOCATION';

        return 'UNKNOWN';
    }

    /**
     * Extracts token definitions from ZIP entries under tokens/.
     */
    private extractTokens(entries: AdmZip.IZipEntry[]): ExtractedToken[] {
        const tokens: ExtractedToken[] = [];

        for (const entry of entries) {
            if (!entry.entryName.startsWith('tokens/') || entry.isDirectory) continue;

            try {
                const json = JSON.parse(entry.getData().toString('utf-8'));
                tokens.push({
                    tokenName: json.tokenName || json.name || null,
                    tokenSymbol: json.tokenSymbol || json.symbol || null,
                    tokenType: json.tokenType || json.type || null,
                    decimals: json.decimals ?? null,
                });
            } catch {
                this.logger.warn(`Failed to parse token file: ${entry.entryName}`);
            }
        }

        return tokens;
    }

    @OnWorkerEvent('failed')
    onFailed(job: Job<PolicyIngestJobData>, error: Error): void {
        this.logger.error(
            `Policy ingest job ${job.id} failed for CID ${job.data.cid}: ${error.message}`,
            error.stack,
        );
    }
}

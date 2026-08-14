import { Injectable, Logger } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { ConfigService } from '@nestjs/config';
import { Queue } from 'bullmq';
import { DataSource } from 'typeorm';
import { QUEUE_NAMES, getWorkerNetwork } from '@shared/config/bullmq.config';
import { ROOT_TOPICS } from '@shared/config/configuration';
import { GuardianEventLogService } from './guardian-event-log.service';

interface AuditMeta {
    instanceId: string;
    subject: string;
}

/**
 * Translates a Guardian Application-Events subject + payload into a targeted job
 * on the worker's EXISTING per-network queues. Events are TRIGGERS, never direct
 * writers of message/business_view rows — the targeted mirror/IPFS fetch
 * materialises the canonical row against the real Hedera consensusTimestamp.
 *
 * Every event that results in a trigger is recorded to guardian_event_log (audit
 * only — observability, not a source of truth). Ignored events are not recorded.
 *
 * Contract:
 *   - route() NEVER throws (it is called per stream event; a malformed payload
 *     logs at debug and returns).
 *   - Every enqueue uses a STABLE jobId + removeOnComplete. jobIds match the
 *     canonical conventions so event and poll paths dedupe to one job.
 *   - enqueueTopicSync() targets TOPIC_SYNC_PRIORITY, a separate small queue,
 *     not the bulk TOPIC_SYNC crawl (priority/lifo ordering on that one proved
 *     unreliable at 100k+ jobs — see topic-sync-priority.processor.ts).
 */
@Injectable()
export class GuardianEventRouter {
    private readonly logger = new Logger(GuardianEventRouter.name);
    private readonly network = getWorkerNetwork();

    /** Hedera addresses every entity as `shard.realm.num`. */
    private static readonly HEDERA_ENTITY_ID = /^\d+\.\d+\.\d+$/;
    private readonly seedTopicId: string;

    constructor(
        @InjectQueue(QUEUE_NAMES.IPFS_FETCH) private readonly ipfsQueue: Queue,
        @InjectQueue(QUEUE_NAMES.TOKEN_SYNC) private readonly tokenQueue: Queue,
        @InjectQueue(QUEUE_NAMES.TOPIC_SYNC_PRIORITY) private readonly topicQueue: Queue,
        private readonly eventLog: GuardianEventLogService,
        private readonly dataSource: DataSource,
        private readonly configService: ConfigService,
    ) {
        this.seedTopicId = this.configService.get<string>('app.seedTopicId')
            || ROOT_TOPICS[this.network]
            || '';
    }

    async route(subject: string, payload: unknown, instanceId: string): Promise<void> {
        const meta: AuditMeta = { instanceId, subject };
        try {
            const key = subject.includes('.')
                ? subject.slice(subject.lastIndexOf('.') + 1)
                : subject;
            const p = payload && typeof payload === 'object'
                ? (payload as Record<string, unknown>)
                : null;

            switch (key) {
                case 'ipfs_added_file':
                    await this.onIpfsAdded(meta, payload);
                    break;
                case 'token_minted':
                    await this.onTokenMinted(meta, p);
                    break;
                case 'block_complete':
                    await this.onBlockComplete(meta, p);
                    break;
                case 'block_event':
                    await this.onBlockEvent(meta, payload);
                    break;
                case 'policy-engine-event-publish-policies':
                case 'policy-event-policy-ready':
                    await this.onPolicyLifecycle(meta, p);
                    break;
                default:
                    // token_mint_complete, error_logs, ipfs hooks, mrv-data, … → ignore (not a trigger).
                    break;
            }
        } catch (err) {
            // Defensive: a router failure must never break the stream loop.
            this.logger.debug(
                `route(${subject}) skipped: ${err instanceof Error ? err.message : String(err)}`,
            );
        }
    }

    /** Records one audit row for a trigger. Best-effort (the service swallows errors). */
    private audit(meta: AuditMeta, refType: string | null, refId: string | null, action: string): Promise<void> {
        return this.eventLog.record({
            network: this.network,
            instanceId: meta.instanceId,
            subject: meta.subject,
            refType,
            refId,
            action,
        });
    }

    /**
     * A fresh CID was pinned → warm the IPFS cache via the canonical fetch path.
     *
     * The AEM docs show this payload as `{cid, url}`, but Guardian's actual
     * publish call (worker-service `worker.ts`) sends the bare CID string —
     * `this.publish(ExternalMessageEvents.IPFS_ADDED_FILE, cid)` — and the AEM
     * HTTP layer forwards NATS payloads untouched. Accept both shapes.
     */
    private async onIpfsAdded(meta: AuditMeta, payload: unknown): Promise<void> {
        const cid = typeof payload === 'string'
            ? payload
            : (payload && typeof payload === 'object' && typeof (payload as Record<string, unknown>)['cid'] === 'string')
                ? (payload as Record<string, unknown>)['cid'] as string
                : null;
        if (!cid) {
            this.logger.debug(`ipfs_added_file: no cid extracted from payload=${JSON.stringify(payload)}`);
            return;
        }
        await this.ipfsQueue.add(
            'fetch',
            { cid, messageTimestamp: '' },
            { jobId: `ipfs-${cid}`, removeOnComplete: true },
        );
        this.logger.log(`new file pinned cid=${cid} -> IPFS fetch enqueued (worker classifies registry/policy/VC)`);
        await this.audit(meta, 'cid', cid, 'ipfs-fetch enqueued');
    }

    /**
     * A token was minted → refresh that token's serials/supply.
     *
     * Guardian also emits this event for draft tokens, which are configured in
     * its own database and never created on Hedera. Those carry a generated UUID
     * where a token ID belongs, so the identifier's shape is what separates a
     * mint worth syncing from a draft the ledger has never heard of.
     */
    private async onTokenMinted(meta: AuditMeta, p: Record<string, unknown> | null): Promise<void> {
        const tokenId = p && typeof p['tokenId'] === 'string' ? (p['tokenId'] as string) : null;
        if (!tokenId) return;
        if (!GuardianEventRouter.HEDERA_ENTITY_ID.test(tokenId)) {
            this.logger.debug(
                `token_minted ignored: "${tokenId}" is a draft token, not a ledger token id`,
            );
            return;
        }
        await this.tokenQueue.add(
            'sync',
            { tokenId, fetchNfts: true, fromSerial: 0 },
            { jobId: `token-${tokenId}-evt`, removeOnComplete: true },
        );
        this.logger.log(`token minted tokenId=${tokenId} -> token sync enqueued`);
        await this.audit(meta, 'token', tokenId, 'token-sync enqueued');
    }

    /** A block-data chain settled → trigger a targeted sync of the policy's topic. */
    private async onBlockComplete(meta: AuditMeta, p: Record<string, unknown> | null): Promise<void> {
        if (!p) return;
        const status = typeof p['status'] === 'string' ? (p['status'] as string) : '';
        if (status !== 'success') return;
        const policyId = typeof p['policyId'] === 'string' ? (p['policyId'] as string) : '';
        if (!policyId) return;

        const topicId = await this.resolvePolicyTopic(policyId);
        if (topicId) {
            await this.enqueueTopicSync(topicId);
        } else {
            // Policy not crawled locally yet — no topic to target. Wake the
            // registry topic instead of doing nothing: it's where this policy
            // gets announced, and it's likely sitting on the bulk queue's
            // backoff rather than the priority lane (it was discovered long
            // before this specific policy existed, so it never got
            // oneTimePriority). The next block_complete (Guardian re-fires
            // these every few seconds) resolves once that catches up.
            await this.wakeSeedTopic();
        }
        this.logger.log(
            `policy block settled policyId=${policyId} status=${status}` +
            (topicId ? ` -> topic ${topicId} sync enqueued` : ' (policy topic not yet known locally — woke registry topic)'),
        );
        await this.audit(meta, 'policy', policyId, topicId ? `topic-sync ${topicId}` : 'no topic resolved — woke registry');
    }

    /**
     * Policy block produced an external event. The documented payload carries no
     * topicId/policyId, so we can only act defensively when one is present.
     */
    private async onBlockEvent(meta: AuditMeta, payload: unknown): Promise<void> {
        const entries = Array.isArray(payload) ? payload : [];
        for (const entry of entries) {
            if (!entry || typeof entry !== 'object') continue;
            const e = entry as Record<string, unknown>;
            const type = typeof e['type'] === 'string' ? (e['type'] as string) : '';
            if (type !== 'Set' && type !== 'Run') continue;
            const policyId = typeof e['policyId'] === 'string' ? (e['policyId'] as string) : '';
            if (!policyId) continue; // no topic resolvable from the documented shape → drop
            const topicId = await this.resolvePolicyTopic(policyId);
            if (topicId) {
                await this.enqueueTopicSync(topicId);
                this.logger.log(`policy block event (${type}) policyId=${policyId} -> topic ${topicId} sync enqueued`);
                await this.audit(meta, 'policy', policyId, `topic-sync ${topicId}`);
            } else {
                await this.wakeSeedTopic();
                await this.audit(meta, 'policy', policyId, 'no topic resolved — woke registry');
            }
        }
    }

    /**
     * Policy published / ready. Payload shape is undocumented (Phase 0): only act
     * on a plainly-present top-level topic/policy id, never parse nested fields.
     */
    private async onPolicyLifecycle(meta: AuditMeta, p: Record<string, unknown> | null): Promise<void> {
        if (!p) return;
        const directTopic =
            (typeof p['instanceTopicId'] === 'string' && p['instanceTopicId']) ||
            (typeof p['policyTopicId'] === 'string' && p['policyTopicId']) ||
            (typeof p['topicId'] === 'string' && p['topicId']) || '';
        if (directTopic) {
            await this.enqueueTopicSync(directTopic as string);
            this.logger.log(`policy published/ready -> topic ${directTopic} sync enqueued`);
            await this.audit(meta, 'topic', directTopic as string, `topic-sync ${directTopic}`);
            return;
        }
        const policyId = typeof p['policyId'] === 'string' ? (p['policyId'] as string) : '';
        if (!policyId) return;
        const topicId = await this.resolvePolicyTopic(policyId);
        if (topicId) {
            await this.enqueueTopicSync(topicId);
            this.logger.log(`policy published/ready policyId=${policyId} -> topic ${topicId} sync enqueued`);
            await this.audit(meta, 'policy', policyId, `topic-sync ${topicId}`);
        } else {
            await this.wakeSeedTopic();
            await this.audit(meta, 'policy', policyId, 'no topic resolved — woke registry');
        }
    }

    /** Indexed lookup: policyId → the instance topic (where VCs live), else policy topic. */
    private async resolvePolicyTopic(policyId: string): Promise<string | null> {
        const rows: Array<{ policyTopicId: string | null; instanceTopicId: string | null }> =
            await this.dataSource.query(
                `SELECT "policyTopicId", "instanceTopicId" FROM policy WHERE "policyId" = $1 LIMIT 1`,
                [policyId],
            );
        const row = rows[0];
        if (!row) return null;
        return row.instanceTopicId || row.policyTopicId || null;
    }

    /**
     * Forces an immediate priority re-poll of the registry/root topic. Used
     * when a policy-related event can't be resolved to a specific topic (the
     * policy hasn't been crawled locally yet, so `policy` has no row for it).
     * The registry topic is where a new policy gets announced, but unlike a
     * genuinely new topic it was discovered long ago, so it never got
     * `oneTimePriority` — left alone, it can sit on the bulk queue's backoff
     * for a long time even though a message relevant right now just landed
     * on it. A no-op if no seed topic is configured.
     */
    private async wakeSeedTopic(): Promise<void> {
        if (!this.seedTopicId) return;
        await this.enqueueTopicSync(this.seedTopicId);
    }

    /**
     * Targeted topic sync. Pre-remove the stable jobId then re-add so a repeated
     * event still fires (the topic-sync paging is watermark-based + idempotent).
     * fromSequenceNumber:0 lets topic-sync resume from the persisted watermark.
     */
    private async enqueueTopicSync(topicId: string): Promise<void> {
        const jobId = `topic-${topicId}-evt`;
        try {
            await this.topicQueue.remove(jobId);
        } catch {
            // Job didn't exist — fine.
        }
        // Targets TOPIC_SYNC_PRIORITY (injected as topicQueue above), not the
        // bulk TOPIC_SYNC crawl — see the class doc comment for why.
        await this.topicQueue.add(
            'sync',
            { topicId, fromSequenceNumber: 0, isOrgTopic: true },
            { jobId, removeOnComplete: true },
        );
    }
}

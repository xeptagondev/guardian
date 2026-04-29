import {
    Processor,
    WorkerHost,
    OnWorkerEvent,
    InjectQueue,
} from "@nestjs/bullmq";
import { Logger } from "@nestjs/common";
import { Job, Queue } from "bullmq";
import { DataSource } from "typeorm";
import { QUEUE_NAMES } from "@shared/config/bullmq.config";
import {
    ParsedMessage,
    DiscoveredTopic,
    decodeBase64Message,
    parseMessageJson,
    extractDiscoverableTopics,
    extractTokenIds,
} from "@shared/utils/message-parser";

export interface MessageProcessJobData {
    consensusTimestamp: string;
    topicId: string;
}

@Processor(QUEUE_NAMES.MESSAGE_PARSE)
export class MessageProcessProcessor extends WorkerHost {
    private readonly logger = new Logger(MessageProcessProcessor.name);

    constructor(
        private readonly dataSource: DataSource,
        @InjectQueue(QUEUE_NAMES.IPFS_FETCH) private readonly ipfsQueue: Queue,
        @InjectQueue(QUEUE_NAMES.POLICY_INGEST) private readonly policyIngestQueue: Queue,
        @InjectQueue(QUEUE_NAMES.TOPIC_SYNC) private readonly topicQueue: Queue,
        @InjectQueue(QUEUE_NAMES.TOKEN_SYNC) private readonly tokenQueue: Queue,
    ) {
        super();
    }

    async process(job: Job<MessageProcessJobData>): Promise<void> {
        const { consensusTimestamp, topicId } = job.data;

        // Read from message_cache
        const rows = await this.dataSource.query(
            `SELECT * FROM message_cache WHERE "consensusTimestamp" = $1 LIMIT 1`,
            [consensusTimestamp],
        );

        if (rows.length === 0) {
            this.logger.warn(
                `Message cache entry not found for ${consensusTimestamp}`,
            );
            return;
        }

        const cacheEntry = rows[0];

        // Base64 decode the message
        const decoded = decodeBase64Message(cacheEntry.message);
        if (!decoded) {
            this.logger.warn(
                `Failed to base64 decode message ${consensusTimestamp}`,
            );
            await this.updateCacheStatus(consensusTimestamp, "DECODE_ERROR");
            return;
        }

        // Parse JSON
        const parsed = parseMessageJson(decoded);
        if (!parsed) {
            this.logger.warn(
                `Failed to parse JSON for message ${consensusTimestamp}`,
            );
            await this.updateCacheStatus(consensusTimestamp, "PARSE_ERROR");
            return;
        }

        // Upsert into message table
        await this.dataSource.query(
            `INSERT INTO message (
                "consensusTimestamp",
                "topicId",
                owner,
                uuid,
                type,
                action,
                status,
                "statusReason",
                "statusMessage",
                lang,
                "responseType",
                "sequenceNumber",
                files,
                options,
                topics,
                tokens,
                "dataSource",
                "lastUpdate",
                "createdAt",
                "updatedAt"
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 'mirror_node', $17, NOW(), NOW())
            ON CONFLICT ("consensusTimestamp") DO UPDATE SET
                owner = COALESCE(EXCLUDED.owner, message.owner),
                uuid = COALESCE(EXCLUDED.uuid, message.uuid),
                type = EXCLUDED.type,
                action = EXCLUDED.action,
                status = COALESCE(EXCLUDED.status, message.status),
                "statusReason" = COALESCE(EXCLUDED."statusReason", message."statusReason"),
                "statusMessage" = COALESCE(EXCLUDED."statusMessage", message."statusMessage"),
                lang = COALESCE(EXCLUDED.lang, message.lang),
                "responseType" = COALESCE(EXCLUDED."responseType", message."responseType"),
                "sequenceNumber" = EXCLUDED."sequenceNumber",
                files = EXCLUDED.files,
                options = COALESCE(message.options, '{}'::jsonb) || COALESCE(EXCLUDED.options, '{}'::jsonb),
                topics = EXCLUDED.topics,
                tokens = EXCLUDED.tokens,
                "dataSource" = CASE
                    WHEN message."dataSource" = 'guardian_api' THEN 'both'
                    ELSE 'mirror_node'
                END,
                "lastUpdate" = EXCLUDED."lastUpdate",
                "updatedAt" = NOW()`,
            [
                consensusTimestamp,
                topicId,
                parsed.owner || cacheEntry.owner,
                parsed.uuid,
                parsed.type,
                parsed.action,
                parsed.status,
                parsed.statusReason,
                parsed.statusMessage,
                parsed.lang,
                parsed.responseType,
                cacheEntry.sequenceNumber,
                parsed.files.length > 0 ? parsed.files : null,
                Object.keys(parsed.options).length > 0
                    ? JSON.stringify(parsed.options)
                    : null,
                parsed.topics.length > 0 ? parsed.topics : null,
                parsed.tokens.length > 0 ? parsed.tokens : null,
                Date.now().toString(),
            ],
        );

        // Route IPFS fetch: Instance-Policy ZIPs go to POLICY_INGEST,
        // everything else goes to IPFS_FETCH as before.
        if (
            parsed.type === 'Instance-Policy'
            && parsed.action === 'publish-policy'
            && parsed.files.length > 0
        ) {
            const instanceTopicId = (parsed.options.topicId as string)
                || (parsed.options.instanceTopicId as string)
                || null;

            await this.policyIngestQueue.add('ingest', {
                cid: parsed.files[0],
                messageTimestamp: consensusTimestamp,
                policyTopicId: topicId,
                instanceTopicId,
                owner: parsed.owner,
                policyName: (parsed.options.name as string) || null,
                policyVersion: (parsed.options.version as string) || null,
                policyUuid: (parsed.options.uuid as string) || null,
            }, {
                jobId: `policy-ingest-${parsed.files[0]}`,
            });
        } else {
            for (const cid of parsed.files) {
                await this.ipfsQueue.add('fetch', {
                    cid,
                    messageTimestamp: consensusTimestamp,
                }, {
                    jobId: `ipfs-${cid}`,
                });
            }
        }

        // Discover and enqueue child topics, storing hierarchy metadata
        const discoveredTopics = extractDiscoverableTopics(parsed, topicId);
        for (const topic of discoveredTopics) {
            // Determine initial status: DYNAMIC_TOPICs are STOPPED until
            // their parent policy is decoded. All other topic types start NEW.
            const initialStatus = await this.resolveTopicInitialStatus(topic);

            // Upsert topic_cache with hierarchy metadata
            await this.dataSource.query(
                `INSERT INTO topic_cache (
                    "topicId", status, messages, "hasNext", "lastUpdate",
                    "topicType", "parentTopicId", "policyTopicId"
                ) VALUES ($1, $2, 0, true, $3, $4, $5, $6)
                ON CONFLICT ("topicId") DO UPDATE SET
                    "topicType" = COALESCE(EXCLUDED."topicType", topic_cache."topicType"),
                    "parentTopicId" = COALESCE(EXCLUDED."parentTopicId", topic_cache."parentTopicId"),
                    "policyTopicId" = COALESCE(EXCLUDED."policyTopicId", topic_cache."policyTopicId")`,
                [
                    topic.topicId,
                    initialStatus,
                    Date.now(),
                    topic.topicType,
                    topic.parentTopicId,
                    // For DYNAMIC_TOPICs, policyTopicId is the parent (instance topic)
                    topic.topicType === 'DYNAMIC_TOPIC' ? topic.parentTopicId : null,
                ],
            );

            // Only enqueue sync if the topic is not STOPPED
            if (initialStatus !== 'STOPPED') {
                await this.topicQueue.add('sync', {
                    topicId: topic.topicId,
                    fromSequenceNumber: 0,
                    isOrgTopic: topic.isOrgTopic,
                }, {
                    jobId: `topic-${topic.topicId}-0`,
                    priority: topic.isOrgTopic ? 1 : 10,
                });
            } else {
                this.logger.debug(
                    `Topic ${topic.topicId} (${topic.topicType}) STOPPED — waiting for parent policy decode`,
                );
            }
        }

        // Update cache status
        await this.updateCacheStatus(consensusTimestamp, "PROCESSED");

        this.logger.debug(
            `Processed message ${consensusTimestamp}: type=${parsed.type} action=${parsed.action}`,
        );
    }

    /**
     * Determines the initial topic_cache status for a newly discovered topic.
     * DYNAMIC_TOPICs are STOPPED until their parent Instance-Policy's ZIP is decoded.
     * All other topic types start as NEW (ready to sync immediately).
     */
    private async resolveTopicInitialStatus(topic: DiscoveredTopic): Promise<string> {
        if (topic.topicType !== 'DYNAMIC_TOPIC' || !topic.parentTopicId) {
            return 'NEW';
        }

        // Check if the parent policy is already decoded
        const rows = await this.dataSource.query(
            `SELECT status FROM policy WHERE "instanceTopicId" = $1 LIMIT 1`,
            [topic.parentTopicId],
        );

        if (rows.length > 0 && rows[0].status === 'DECODED') {
            return 'NEW'; // Parent policy is ready, proceed immediately
        }

        return 'STOPPED';
    }

    private async updateCacheStatus(consensusTimestamp: string, status: string): Promise<void> {
        await this.dataSource.query(
            `UPDATE message_cache SET status = $1, "lastUpdate" = $2 WHERE "consensusTimestamp" = $3`,
            [status, Date.now().toString(), consensusTimestamp],
        );
    }

    @OnWorkerEvent("failed")
    onFailed(job: Job<MessageProcessJobData>, error: Error): void {
        this.logger.error(
            `Message process job ${job.id} failed for ${job.data.consensusTimestamp}: ${error.message}`,
            error.stack,
        );
    }
}

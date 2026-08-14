import { Processor, WorkerHost, OnWorkerEvent, InjectQueue } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Job, Queue } from 'bullmq';
import { DataSource } from 'typeorm';
import { QUEUE_NAMES } from '@shared/config/bullmq.config';
import { HederaService, TopicMessage } from '../services/hedera.service';
import { isTopicBlocked } from '@shared/config/topic-blocklist';
import { TopicSyncJobData } from './topic-sync.processor';

/**
 * Same sync logic as TopicSyncProcessor, on a physically separate queue that
 * holds the root/registry topic, guardian-sync's event-triggered syncs, and
 * newly-discovered topics catching up on their first sync — never the
 * six-figure routine-repoll backlog TOPIC_SYNC carries.
 *
 * A separate queue instead of `priority`/`lifo` on TOPIC_SYNC because neither
 * reliably jumped a job to the front once that queue hit 100k+ jobs (tested
 * against this project's Redict instance).
 *
 * `oneTimePriority` jobs (first discovery of a topic, see
 * message-process.processor.ts) are handed back to the bulk TOPIC_SYNC queue
 * once caught up, so this queue doesn't inherit TOPIC_SYNC's steady-state
 * churn and grow the same way.
 */
@Processor(QUEUE_NAMES.TOPIC_SYNC_PRIORITY)
export class TopicSyncPriorityProcessor extends WorkerHost {
    private readonly logger = new Logger(TopicSyncPriorityProcessor.name);
    private readonly pollDelay: number;
    private readonly orgPollDelay: number;
    private readonly maxPollDelay: number;

    constructor(
        private readonly hederaService: HederaService,
        private readonly dataSource: DataSource,
        private readonly configService: ConfigService,
        @InjectQueue(QUEUE_NAMES.MESSAGE_PARSE) private readonly messageQueue: Queue,
        @InjectQueue(QUEUE_NAMES.TOPIC_SYNC_PRIORITY) private readonly priorityQueue: Queue,
        @InjectQueue(QUEUE_NAMES.TOPIC_SYNC) private readonly bulkTopicQueue: Queue,
    ) {
        super();
        this.pollDelay = this.configService.get<number>('app.mirrorNodePollDelay') ?? 30000;
        this.orgPollDelay = Math.max(1000, Math.floor(this.pollDelay / 3));
        this.maxPollDelay = this.configService.get<number>('app.mirrorNodeMaxPollDelay') ?? 1_800_000;
    }

    async process(job: Job<TopicSyncJobData>): Promise<void> {
        const { topicId, fromSequenceNumber, isOrgTopic, emptyPollStreak = 0, oneTimePriority = false } = job.data;

        if (isTopicBlocked(topicId)) {
            this.logger.debug(`Topic ${topicId} is blocklisted — skipping sync`);
            return;
        }

        this.logger.log(`Syncing topic ${topicId} from seq ${fromSequenceNumber} (priority lane)`);

        const { messages } = await this.hederaService.getMessages(topicId, fromSequenceNumber);

        if (messages.length === 0) {
            // A one-time-priority topic that comes up empty is already caught
            // up — hand steady-state re-polling back to the bulk queue instead
            // of staying on the priority lane forever.
            if (oneTimePriority) {
                await this.bulkTopicQueue.add('sync', {
                    topicId,
                    fromSequenceNumber,
                    isOrgTopic,
                    emptyPollStreak: 0,
                }, {
                    jobId: `topic-${topicId}-poll-${Date.now()}`,
                    delay: isOrgTopic ? this.orgPollDelay : this.pollDelay,
                    removeOnComplete: true,
                    removeOnFail: 1000,
                });
                this.logger.debug(`Topic ${topicId} caught up — handing off to bulk TOPIC_SYNC`);
                return;
            }

            const baseDelay = isOrgTopic ? this.orgPollDelay : this.pollDelay;
            const streak = emptyPollStreak + 1;
            const delay = Math.min(baseDelay * 2 ** Math.min(streak, 10), this.maxPollDelay);
            await this.priorityQueue.add('sync', {
                topicId,
                fromSequenceNumber,
                isOrgTopic,
                emptyPollStreak: streak,
            }, {
                jobId: `topic-${topicId}-poll-${Date.now()}`,
                delay,
                removeOnComplete: true,
                removeOnFail: 1000,
            });
            this.logger.debug(`No new messages for topic ${topicId}, re-polling in ${delay}ms (streak=${streak})`);
            return;
        }

        const maxSequence = Math.max(...messages.map(m => m.sequence_number));
        const hasNext = messages.length >= 100;
        const now = Date.now().toString();

        await this.batchInsertMessages(messages, topicId, now);

        await this.messageQueue.addBulk(
            messages.map(msg => ({
                name: 'process',
                data: {
                    consensusTimestamp: msg.consensus_timestamp,
                    topicId,
                    fromPriorityLane: true,
                },
                opts: {
                    priority: 1,
                    jobId: `msg-${msg.consensus_timestamp}`,
                    removeOnComplete: true,
                    removeOnFail: 1000,
                },
            })),
        );

        await this.dataSource.query(
            `INSERT INTO topic_cache ("topicId", messages, "hasNext", "lastUpdate", status)
             VALUES ($4, $1, $2, $3, 'SYNCED')
             ON CONFLICT ("topicId") DO UPDATE SET
                 messages = EXCLUDED.messages,
                 "hasNext" = EXCLUDED."hasNext",
                 "lastUpdate" = EXCLUDED."lastUpdate",
                 status = 'SYNCED'`,
            [maxSequence, hasNext, now, topicId],
        );

        const targetQueue = (!hasNext && oneTimePriority) ? this.bulkTopicQueue : this.priorityQueue;
        const nextDelay = hasNext ? 100 : (isOrgTopic ? this.orgPollDelay : this.pollDelay);
        await targetQueue.add('sync', {
            topicId,
            fromSequenceNumber: maxSequence,
            isOrgTopic,
            emptyPollStreak: 0,
            oneTimePriority: hasNext ? oneTimePriority : false,
        }, {
            jobId: `topic-${topicId}-${maxSequence}-${Date.now()}`,
            delay: nextDelay,
            removeOnComplete: true,
            removeOnFail: 1000,
        });

        this.logger.log(
            `Topic ${topicId} (priority lane): ${messages.length} messages, maxSeq=${maxSequence}, hasNext=${hasNext}`,
        );
    }

    /** Same batching approach as TopicSyncProcessor — see that file for rationale. */
    private async batchInsertMessages(
        messages: TopicMessage[],
        topicId: string,
        now: string,
    ): Promise<void> {
        const queryRunner = this.dataSource.createQueryRunner();
        await queryRunner.connect();
        await queryRunner.startTransaction();

        try {
            const timestamps: string[] = [];
            const topicIds: string[] = [];
            const bodies: string[] = [];
            const seqNums: number[] = [];
            const chunkIds: (string | null)[] = [];
            const chunkNums: (number | null)[] = [];
            const chunkTotals: (number | null)[] = [];

            for (const msg of messages) {
                timestamps.push(msg.consensus_timestamp);
                topicIds.push(topicId);
                bodies.push(msg.message);
                seqNums.push(msg.sequence_number);

                const rawChunkId = msg.chunk_info?.initial_transaction_id;
                chunkIds.push(
                    rawChunkId
                        ? (typeof rawChunkId === 'string' ? rawChunkId : JSON.stringify(rawChunkId))
                        : null,
                );
                chunkNums.push(msg.chunk_info?.number ?? null);
                chunkTotals.push(msg.chunk_info?.total ?? null);
            }

            await queryRunner.query(
                `INSERT INTO message_cache (
                    "consensusTimestamp", "topicId", status, "lastUpdate",
                    message, "sequenceNumber", owner,
                    "chunkId", "chunkNumber", "chunkTotal"
                )
                SELECT
                    unnest($1::text[]),
                    unnest($2::text[]),
                    'LOADED',
                    $3,
                    unnest($4::text[]),
                    unnest($5::int[]),
                    NULL,
                    unnest($6::text[]),
                    unnest($7::int[]),
                    unnest($8::int[])
                ON CONFLICT ("consensusTimestamp") DO UPDATE SET
                    message = EXCLUDED.message,
                    status = 'LOADED',
                    "lastUpdate" = EXCLUDED."lastUpdate"`,
                [timestamps, topicIds, now, bodies, seqNums, chunkIds, chunkNums, chunkTotals],
            );

            await queryRunner.commitTransaction();
        } catch (error) {
            await queryRunner.rollbackTransaction();
            throw error;
        } finally {
            await queryRunner.release();
        }
    }

    @OnWorkerEvent('failed')
    onFailed(job: Job<TopicSyncJobData>, error: Error): void {
        this.logger.error(
            `Priority topic sync job ${job.id} failed for topic ${job.data.topicId}: ${error.message}`,
            error.stack,
        );
    }
}

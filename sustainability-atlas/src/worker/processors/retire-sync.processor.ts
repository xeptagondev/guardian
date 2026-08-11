import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { DataSource } from 'typeorm';
import { QUEUE_NAMES } from '@shared/config/bullmq.config';
import { HederaService } from '../services/hedera.service';
import { RETIRE_EXECUTED_TOPIC, decodeRetireEvent } from '../services/retire-event.decoder';

export interface RetireSyncJobData {
    contractId: string;
}

/**
 * Ingests executed retirement events from one Guardian RETIRE contract.
 *
 * Retirement has until now been *inferred* from Mirror Node marking an NFT
 * serial deleted, which yields a count and nothing else — no date, no actor, and
 * nothing at all for fungible tokens. The retire contract emits the real record:
 * who retired, which token, how much, and exactly which serials.
 *
 * Only RETIRE_EXECUTED_TOPIC is ingested; see the decoder for why the visually
 * identical request event must not be counted.
 */
@Processor(QUEUE_NAMES.RETIRE_SYNC)
export class RetireSyncProcessor extends WorkerHost {
    private readonly logger = new Logger(RetireSyncProcessor.name);

    /** Pages of contract history per job. The watermark persists, so a contract
     *  with a longer history finishes on later passes. */
    private static readonly MAX_PAGES = 20;

    constructor(
        private readonly hederaService: HederaService,
        private readonly dataSource: DataSource,
    ) {
        super();
    }

    async process(job: Job<RetireSyncJobData>): Promise<void> {
        const { contractId } = job.data;

        const [row]: Array<{ log_watermark: string | null }> = await this.dataSource.query(
            `SELECT log_watermark FROM contract_cache WHERE contract_id = $1`,
            [contractId],
        );
        let watermark = row?.log_watermark ?? null;
        let ingested = 0;

        for (let page = 0; page < RetireSyncProcessor.MAX_PAGES; page++) {
            const { logs, nextLink } = await this.hederaService.getContractLogs(contractId, watermark);
            if (logs.length === 0) {
                break;
            }

            for (const log of logs) {
                if (log.topics?.[0] !== RETIRE_EXECUTED_TOPIC) {
                    continue;
                }
                const event = decodeRetireEvent(log.data);
                if (!event) {
                    // Right signature, unexpected payload — flag rather than guess.
                    this.logger.warn(
                        `Contract ${contractId} log ${log.timestamp}#${log.index} matched the retire ` +
                        `signature but did not decode — skipped`,
                    );
                    continue;
                }

                for (const token of event.tokens) {
                    // count vs serials is resolved downstream against the token's
                    // real type: several events populate both fields.
                    await this.dataSource.query(
                        `INSERT INTO token_retire_event (
                            consensus_timestamp, log_index, token_id, contract_id, account_id, amount, serials
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                         ON CONFLICT (consensus_timestamp, log_index, token_id) DO UPDATE SET
                            contract_id = EXCLUDED.contract_id,
                            account_id  = EXCLUDED.account_id,
                            amount      = EXCLUDED.amount,
                            serials     = EXCLUDED.serials`,
                        [
                            log.timestamp,
                            log.index,
                            token.tokenId,
                            contractId,
                            event.accountId,
                            token.count,
                            token.serials,
                        ],
                    );
                    ingested++;
                }
            }

            watermark = logs[logs.length - 1].timestamp;
            await this.dataSource.query(
                `UPDATE contract_cache SET log_watermark = $1, last_update = $2 WHERE contract_id = $3`,
                [watermark, Date.now().toString(), contractId],
            );

            if (!nextLink) {
                break;
            }
        }

        if (ingested > 0) {
            this.logger.log(`Contract ${contractId}: ingested ${ingested} retirement record(s)`);
        }
    }

    @OnWorkerEvent('failed')
    onFailed(job: Job<RetireSyncJobData>, error: Error): void {
        this.logger.error(
            `Retire sync job ${job.id} failed for ${job.data.contractId}: ${error.message}`,
            error.stack,
        );
    }
}

import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { QUEUE_NAMES } from '@shared/config/bullmq.config';
import { ProjectSchemaResolverService } from '../services/project-extraction/project-schema-resolver.service';
import { ProjectExtractorService } from '../services/project-extraction/project-extractor.service';

export interface ProjectExtractJobData {
    /** Optional: focus on a single instance topic (used by triggered runs). */
    instanceTopicId?: string;
}

/**
 * Two-phase project extraction:
 *
 *  1. resolve: identify the project schema(s) per DECODED policy and persist
 *     the field mapping into project_schema_resolution.
 *  2. extract: scan VC messages in DYNAMIC_TOPICs of resolved policies and
 *     upsert canonical project rows.
 *
 * Both phases are idempotent and run on the same queue, dispatched by job name:
 *  - `resolve-missing` — sweep all DECODED policies without a resolution
 *  - `resolve-one`     — focus on a single instanceTopicId (faster after policy ingest)
 *  - `extract-missing` — sweep VC messages without a project row
 *  - `sweep`           — runs both resolve-missing and extract-missing (recurring maintenance)
 */
@Processor(QUEUE_NAMES.PROJECT_EXTRACT)
export class ProjectExtractProcessor extends WorkerHost {
    private readonly logger = new Logger(ProjectExtractProcessor.name);

    constructor(
        private readonly resolver: ProjectSchemaResolverService,
        private readonly extractor: ProjectExtractorService,
    ) {
        super();
    }

    async process(job: Job<ProjectExtractJobData>): Promise<void> {
        const { name, data } = job;

        try {
            switch (name) {
                case 'resolve-one':
                    if (!data?.instanceTopicId) {
                        this.logger.warn('resolve-one job missing instanceTopicId, skipping');
                        return;
                    }
                    await this.resolver.resolveByInstanceTopic(data.instanceTopicId);
                    return;

                case 'resolve-missing':
                    await this.resolver.resolveMissing();
                    return;

                case 'extract-missing':
                    await this.extractor.extractMissing();
                    return;

                case 'sweep':
                default:
                    await this.resolver.resolveMissing();
                    await this.extractor.extractMissing();
                    return;
            }
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            this.logger.error(`Project extract job "${name}" failed: ${msg}`,
                err instanceof Error ? err.stack : undefined);
            throw err;
        }
    }

    @OnWorkerEvent('failed')
    onFailed(job: Job<ProjectExtractJobData>, error: Error): void {
        this.logger.error(
            `Project extract job ${job.id} (${job.name}) failed: ${error.message}`,
            error.stack,
        );
    }
}

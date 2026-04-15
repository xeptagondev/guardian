import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { ConflictException, Logger, NotFoundException } from '@nestjs/common';
import { Job } from 'bullmq';
import { DataSource } from 'typeorm';
import JSZip from 'jszip';
import { QUEUE_NAMES } from '@shared/config/bullmq.config';
import { IpfsService } from '../services/ipfs.service';

interface GuardianSchemaField {
    tag: string;
    fieldName: string;
    required: boolean;
    dataType: 'text' | 'number' | 'boolean' | 'enum' | 'array' | 'object';
    selectedSchema?: string;
    options?: string[];
}

interface GuardianSchema {
    uuid: string;
    iri: string;
    name: string;
    description?: string;
    fields: GuardianSchemaField[];
}

interface PublishPolicyRow {
    consensusTimestamp: string;
    files: string[] | null;
}

export interface MethodologySchemaSyncJobData {
    topicId: string;
    consensusTimestamp?: string;
    cid?: string;
}

@Processor(QUEUE_NAMES.METHODOLOGY_SCHEMA_SYNC)
export class MethodologySchemaSyncProcessor extends WorkerHost {
    private readonly logger = new Logger(MethodologySchemaSyncProcessor.name);

    constructor(
        private readonly dataSource: DataSource,
        private readonly ipfsService: IpfsService,
    ) {
        super();
    }

    async process(job: Job<MethodologySchemaSyncJobData>): Promise<void> {
        const { topicId, consensusTimestamp, cid: jobCid } = job.data;

        const rows: PublishPolicyRow[] = await this.dataSource.query(
            `
            SELECT
                m."consensusTimestamp" AS "consensusTimestamp",
                m.files
            FROM message m
            WHERE m."topicId" = $1
              AND m.type = 'Instance-Policy'
              AND m.action = 'publish-policy'
            ORDER BY m."createdAt" DESC NULLS LAST
            `,
            [topicId],
        );

        if (rows.length === 0) {
            throw new NotFoundException(
                `No publish-policy Instance-Policy rows found for topicId "${topicId}"`,
            );
        }

        if (rows.length > 1) {
            throw new ConflictException(
                `Expected exactly one publish-policy Instance-Policy row for topicId "${topicId}", found ${rows.length}`,
            );
        }

        const row = rows[0];
        if (consensusTimestamp && row.consensusTimestamp !== consensusTimestamp) {
            this.logger.warn(
                `Topic ${topicId} publish row consensus mismatch. Job=${consensusTimestamp}, DB=${row.consensusTimestamp}`,
            );
        }

        const cid = jobCid || row.files?.[0];
        if (!cid) {
            throw new NotFoundException(
                `No CID found in files[0] for topicId "${topicId}"`,
            );
        }

        const zipBuffer = await this.ipfsService.fetchContent(cid);
        const schemas = await this.extractSchemasFromZip(zipBuffer);

        for (const schema of schemas) {
            await this.dataSource.query(
                `
                INSERT INTO methodology_schema (
                    "topicId",
                    cid,
                    "schemaUuid",
                    iri,
                    name,
                    description,
                    fields,
                    "createdAt",
                    "updatedAt"
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW(), NOW())
                ON CONFLICT ("topicId", "schemaUuid") DO UPDATE
                SET
                    cid = EXCLUDED.cid,
                    iri = EXCLUDED.iri,
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    fields = EXCLUDED.fields,
                    "updatedAt" = NOW()
                `,
                [
                    topicId,
                    cid,
                    schema.uuid,
                    schema.iri,
                    schema.name,
                    schema.description ?? null,
                    JSON.stringify(schema.fields),
                ],
            );
        }

        this.logger.log(
            `Synced ${schemas.length} methodology schemas for topic ${topicId} (cid=${cid})`,
        );
    }

    private async extractSchemasFromZip(content: Buffer): Promise<GuardianSchema[]> {
        const zip = await JSZip.loadAsync(content);

        const schemaEntries = Object.keys(zip.files)
            .filter((name) => {
                const entry = zip.files[name];
                return !entry.dir && name.startsWith('schemas/') && name.toLowerCase().endsWith('.json');
            })
            .sort((a, b) => a.localeCompare(b));

        const parsedSchemas: GuardianSchema[] = [];
        for (const entryName of schemaEntries) {
            const rawText = await zip.files[entryName].async('string');
            const raw = JSON.parse(rawText) as Record<string, unknown>;
            parsedSchemas.push(this.parseGuardianSchema(raw));
        }

        return parsedSchemas;
    }

    private parseGuardianSchema(raw: Record<string, unknown>): GuardianSchema {
        const doc = (raw.document ?? {}) as Record<string, unknown>;
        const props = (doc.properties ?? {}) as Record<string, Record<string, unknown>>;
        const required = (doc.required ?? []) as string[];
        const skipProps = new Set(['@context', 'type', 'id', 'policyId', 'ref']);

        const fields: GuardianSchemaField[] = [];
        for (const [key, prop] of Object.entries(props)) {
            if (skipProps.has(key)) continue;

            const f: GuardianSchemaField = {
                tag: key,
                fieldName: (prop.description as string) || (prop.title as string) || key,
                required: required.includes(key),
                dataType: 'text',
            };

            const ref = prop.$ref as string | undefined;
            const t = prop.type as string | undefined;
            if (ref) {
                f.dataType = 'object';
                f.selectedSchema = ref;
            } else if (t === 'number' || t === 'integer') {
                f.dataType = 'number';
            } else if (t === 'boolean') {
                f.dataType = 'boolean';
            } else if (t === 'array') {
                const items = (prop.items ?? {}) as Record<string, unknown>;
                const enumVals = (items.enum ?? prop.enum) as string[] | undefined;
                if (enumVals) {
                    f.dataType = 'enum';
                    f.options = enumVals;
                } else {
                    f.dataType = 'array';
                }
            }

            fields.push(f);
        }

        return {
            uuid: raw.uuid as string,
            iri: raw.iri as string,
            name: raw.name as string,
            description: raw.description as string | undefined,
            fields,
        };
    }

    @OnWorkerEvent('failed')
    onFailed(job: Job<MethodologySchemaSyncJobData>, error: Error): void {
        this.logger.error(
            `Methodology schema sync job ${job.id} failed for topic ${job.data.topicId}: ${error.message}`,
            error.stack,
        );
    }
}

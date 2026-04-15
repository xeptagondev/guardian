import { Injectable, ConflictException, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import axios from 'axios';
import JSZip from 'jszip';
import { DataSource } from 'typeorm';
import {
    MethodologyQueryDto,
    MethodologyResponseDto,
    MethodologySchemaSyncResponseDto,
    MethodologySchemaSyncItemDto,
    MethodologySchemaFieldDto,
} from '../dto/methodology.dto';
import { PaginatedResponse } from '../dto/pagination.dto';
import { NetworkDataSourceRegistry } from '../database/network-datasource.registry';
import { PgMethodologyRepository } from '../repositories/pg-methodology.repository';
import { MethodologyRepository } from '../repositories/methodology.repository';

type JsonObject = Record<string, unknown>;

interface PolicyLookupRow {
    sourceTimestamp: string;
    files: string[] | null;
}

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

@Injectable()
export class MethodologiesService {
    constructor(
        private readonly dataSources: NetworkDataSourceRegistry,
    ) {}

    async findAll(
        network: string,
        query: MethodologyQueryDto,
    ): Promise<PaginatedResponse<MethodologyResponseDto>> {
        const repo = this.getRepository(network);
        const page = query.page ?? 1;
        const limit = query.limit ?? 20;

        const result = await repo.findAll({
            page,
            limit,
            search: query.search,
            name: query.name,
            id: query.id,
            description: query.description,
            status: query.status,
            registryDid: query.registryDid,
            registryName: query.registryName,
            version: query.version,
            sortBy: query.sortBy,
            sortDir: query.sortDir,
        });

        const data = result.rows.map(row =>
            MethodologyResponseDto.fromRow(row, network, row.stats),
        );
        return new PaginatedResponse(data, result.total, page, limit);
    }

    async findById(network: string, id: string): Promise<MethodologyResponseDto | null> {
        const repo = this.getRepository(network);
        const row = await repo.findById(id);
        if (!row) return null;
        return MethodologyResponseDto.fromRow(row, network, row.stats);
    }

    async syncSchemasByTopic(
        network: string,
        topicId: string,
    ): Promise<MethodologySchemaSyncResponseDto> {
        const ds = this.dataSources.getDataSource(network);
        await this.ensureMethodologySchemaTable(ds);

        const rows: PolicyLookupRow[] = await ds.query(
            `
            SELECT
                bv."sourceTimestamp" AS "sourceTimestamp",
                m.files
            FROM business_view bv
            JOIN message m
                ON m."consensusTimestamp" = bv."sourceTimestamp"
            WHERE bv."relatedTopicId" = $1
              AND bv."viewType" = 'METHODOLOGY'
              AND m.type = 'Instance-Policy'
              AND m.action = 'publish-policy'
            ORDER BY bv."createdAt" DESC NULLS LAST
            `,
            [topicId],
        );

        if (rows.length === 0) {
            throw new NotFoundException(
                `No publish-policy Instance-Policy row found for topicId "${topicId}" on ${network}`,
            );
        }

        if (rows.length > 1) {
            throw new ConflictException(
                `Expected exactly one publish-policy Instance-Policy row for topicId "${topicId}", found ${rows.length}`,
            );
        }

        const files = rows[0].files;
        if (!Array.isArray(files) || files.length === 0 || typeof files[0] !== 'string') {
            throw new NotFoundException(
                `No CID found in files[0] for topicId "${topicId}" on ${network}`,
            );
        }

        const cid = files[0];
        const zipBuffer = await this.downloadPolicyZipFromIpfs(cid);
        const schemas = await this.extractSchemasFromZip(zipBuffer);

        if (schemas.length === 0) {
            throw new NotFoundException(`No schema JSON files found under schemas/ for CID "${cid}"`);
        }

        for (const schema of schemas) {
            await ds.query(
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

        return {
            network,
            topicId,
            cid,
            schemaCount: schemas.length,
            schemas: schemas.map(this.toSchemaSyncItemDto),
        };
    }

    /**
     * Resolves the appropriate MethodologyRepository for the given network.
     * Currently only PostgreSQL is supported; add a factory here to swap
     * in a different backend implementation.
     */
    private getRepository(network: string): MethodologyRepository {
        const ds = this.dataSources.getDataSource(network);
        return new PgMethodologyRepository(ds);
    }

    private async ensureMethodologySchemaTable(ds: DataSource): Promise<void> {
        await ds.query(`
            CREATE TABLE IF NOT EXISTS methodology_schema (
                id BIGSERIAL PRIMARY KEY,
                "topicId" varchar(30) NOT NULL,
                cid varchar(100) NOT NULL,
                "schemaUuid" varchar(255) NOT NULL,
                iri text NOT NULL,
                name text NOT NULL,
                description text NULL,
                fields jsonb NOT NULL,
                "createdAt" timestamptz NOT NULL DEFAULT NOW(),
                "updatedAt" timestamptz NOT NULL DEFAULT NOW(),
                UNIQUE ("topicId", "schemaUuid")
            )
        `);

        await ds.query(`
            CREATE INDEX IF NOT EXISTS idx_methodology_schema_topic_id
            ON methodology_schema ("topicId")
        `);
    }

    private async downloadPolicyZipFromIpfs(cid: string): Promise<Buffer> {
        const url = `https://ipfs.io/ipfs/${cid}`;

        try {
            const response = await axios.get<ArrayBuffer>(url, {
                responseType: 'arraybuffer',
                timeout: 120000,
            });

            return Buffer.from(response.data);
        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : String(error);
            throw new InternalServerErrorException(
                `Failed to download policy ZIP from ${url}: ${message}`,
            );
        }
    }

    private async extractSchemasFromZip(content: Buffer): Promise<GuardianSchema[]> {
        let zip: JSZip;

        try {
            zip = await JSZip.loadAsync(content);
        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : String(error);
            throw new InternalServerErrorException(`Downloaded CID content is not a valid ZIP: ${message}`);
        }

        const schemaEntries = Object.keys(zip.files)
            .filter((name) => {
                const entry = zip.files[name];
                return !entry.dir && name.startsWith('schemas/') && name.toLowerCase().endsWith('.json');
            })
            .sort((a, b) => a.localeCompare(b));

        const parsedSchemas: GuardianSchema[] = [];
        for (const entryName of schemaEntries) {
            const rawText = await zip.files[entryName].async('string');
            const json = JSON.parse(rawText) as JsonObject;
            parsedSchemas.push(this.parseGuardianSchema(json));
        }

        return parsedSchemas;
    }

    private parseGuardianSchema(raw: JsonObject): GuardianSchema {
        const doc = this.asRecord(raw.document);
        const propsRecord = this.asRecord(doc?.properties);
        const required = Array.isArray(doc?.required)
            ? doc.required.filter((v): v is string => typeof v === 'string')
            : [];

        const skipProps = new Set(['@context', 'type', 'id', 'policyId', 'ref']);
        const fields: GuardianSchemaField[] = [];

        for (const [key, rawProp] of Object.entries(propsRecord ?? {})) {
            if (skipProps.has(key)) continue;
            const prop = this.asRecord(rawProp) ?? {};

            const field: GuardianSchemaField = {
                tag: key,
                fieldName: this.asString(prop.description) ?? this.asString(prop.title) ?? key,
                required: required.includes(key),
                dataType: 'text',
            };

            const ref = this.asString(prop['$ref']);
            const type = this.asString(prop.type);

            if (ref) {
                field.dataType = 'object';
                field.selectedSchema = ref;
            } else if (type === 'number' || type === 'integer') {
                field.dataType = 'number';
            } else if (type === 'boolean') {
                field.dataType = 'boolean';
            } else if (type === 'array') {
                const items = this.asRecord(prop.items) ?? {};
                const enumValues = this.asStringArray(items.enum) ?? this.asStringArray(prop.enum);
                if (enumValues && enumValues.length > 0) {
                    field.dataType = 'enum';
                    field.options = enumValues;
                } else {
                    field.dataType = 'array';
                }
            }

            fields.push(field);
        }

        const uuid = this.asString(raw.uuid);
        const iri = this.asString(raw.iri);
        const name = this.asString(raw.name);

        if (!uuid || !iri || !name) {
            throw new InternalServerErrorException(
                'Schema JSON is missing one of required top-level fields: uuid, iri, name',
            );
        }

        const description = this.asString(raw.description) ?? undefined;

        return {
            uuid,
            iri,
            name,
            description,
            fields,
        };
    }

    private toSchemaSyncItemDto(schema: GuardianSchema): MethodologySchemaSyncItemDto {
        return {
            uuid: schema.uuid,
            iri: schema.iri,
            name: schema.name,
            description: schema.description,
            fields: schema.fields.map((field): MethodologySchemaFieldDto => ({
                tag: field.tag,
                fieldName: field.fieldName,
                required: field.required,
                dataType: field.dataType,
                selectedSchema: field.selectedSchema,
                options: field.options,
            })),
        };
    }

    private asRecord(value: unknown): JsonObject | null {
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            return value as JsonObject;
        }
        return null;
    }

    private asString(value: unknown): string | null {
        return typeof value === 'string' ? value : null;
    }

    private asStringArray(value: unknown): string[] | null {
        if (!Array.isArray(value)) {
            return null;
        }

        const items = value.filter((v): v is string => typeof v === 'string');
        return items.length > 0 ? items : null;
    }
}

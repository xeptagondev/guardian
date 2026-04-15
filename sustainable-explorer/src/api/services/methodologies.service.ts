import { Injectable } from '@nestjs/common';
import {
    MethodologyQueryDto,
    MethodologyResponseDto,
    MethodologySchemasResponseDto,
    MethodologySchemaRecordDto,
} from '../dto/methodology.dto';
import { PaginatedResponse } from '../dto/pagination.dto';
import { NetworkDataSourceRegistry } from '../database/network-datasource.registry';
import { PgMethodologyRepository } from '../repositories/pg-methodology.repository';
import { MethodologyRepository } from '../repositories/methodology.repository';

interface RawMethodologySchemaRow {
    id: string;
    topicId: string;
    cid: string;
    schemaUuid: string;
    iri: string;
    name: string;
    description: string | null;
    fields: Record<string, unknown>[];
    createdAt: Date;
    updatedAt: Date;
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

    async findSchemasByTopic(
        network: string,
        topicId: string,
    ): Promise<MethodologySchemasResponseDto> {
        const ds = this.dataSources.getDataSource(network);

        let rows: RawMethodologySchemaRow[] = [];
        try {
            rows = await ds.query(
                `
                SELECT
                    id,
                    "topicId",
                    cid,
                    "schemaUuid",
                    iri,
                    name,
                    description,
                    fields,
                    "createdAt",
                    "updatedAt"
                FROM methodology_schema
                WHERE "topicId" = $1
                ORDER BY name ASC, "schemaUuid" ASC
                `,
                [topicId],
            );
        } catch (error: unknown) {
            // If worker has not yet bootstrapped this table, return empty data.
            if (!this.isUndefinedTableError(error)) {
                throw error;
            }
        }

        const schemas: MethodologySchemaRecordDto[] = rows.map((row) => ({
            id: row.id,
            topicId: row.topicId,
            cid: row.cid,
            schemaUuid: row.schemaUuid,
            iri: row.iri,
            name: row.name,
            description: row.description,
            fields: this.normalizeFields(row.fields),
            createdAt: row.createdAt,
            updatedAt: row.updatedAt,
        }));

        return {
            network,
            topicId,
            count: schemas.length,
            schemas,
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

    private isUndefinedTableError(error: unknown): boolean {
        return (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            (error as { code?: string }).code === '42P01'
        );
    }

    private normalizeFields(fields: unknown): MethodologySchemaRecordDto['fields'] {
        if (!Array.isArray(fields)) {
            return [];
        }

        return fields
            .filter((field): field is Record<string, unknown> => (
                typeof field === 'object' && field !== null
            ))
            .map((field) => ({
                tag: typeof field.tag === 'string' ? field.tag : '',
                fieldName: typeof field.fieldName === 'string' ? field.fieldName : '',
                required: field.required === true,
                dataType:
                    field.dataType === 'number' ||
                    field.dataType === 'boolean' ||
                    field.dataType === 'enum' ||
                    field.dataType === 'array' ||
                    field.dataType === 'object'
                        ? field.dataType
                        : 'text',
                selectedSchema:
                    typeof field.selectedSchema === 'string' ? field.selectedSchema : undefined,
                options: Array.isArray(field.options)
                    ? field.options.filter((option): option is string => typeof option === 'string')
                    : undefined,
            }));
    }
}

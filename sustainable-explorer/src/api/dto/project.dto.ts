import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, IsInt, Min, Max, IsIn } from 'class-validator';
import { Type } from 'class-transformer';

export class ProjectQueryDto {
    @ApiPropertyOptional({ default: 1, minimum: 1 })
    @IsOptional()
    @Type(() => Number)
    @IsInt()
    @Min(1)
    page?: number = 1;

    @ApiPropertyOptional({ default: 20, minimum: 1, maximum: 200 })
    @IsOptional()
    @Type(() => Number)
    @IsInt()
    @Min(1)
    @Max(200)
    limit?: number = 20;

    @ApiPropertyOptional({ description: 'Free-text search across project name, description, projectId.' })
    @IsOptional()
    @IsString()
    search?: string;

    @ApiPropertyOptional({ description: 'Filter by ISO/display country (exact, case-insensitive).' })
    @IsOptional()
    @IsString()
    country?: string;

    @ApiPropertyOptional({ description: 'Filter by canonical status.' })
    @IsOptional()
    @IsString()
    status?: string;

    @ApiPropertyOptional({ description: 'Filter by vintage / reporting year.' })
    @IsOptional()
    @IsString()
    vintage?: string;

    @ApiPropertyOptional({ description: 'Filter by sector.' })
    @IsOptional()
    @IsString()
    sector?: string;

    @ApiPropertyOptional({ description: 'Filter by project type.' })
    @IsOptional()
    @IsString()
    projectType?: string;

    @ApiPropertyOptional({ description: 'Filter by methodology / policy topic ID.' })
    @IsOptional()
    @IsString()
    methodologyTopicId?: string;

    @ApiPropertyOptional({ enum: ['name', 'country', 'vintage', 'status', 'createdAt'] })
    @IsOptional()
    @IsIn(['name', 'country', 'vintage', 'status', 'createdAt'])
    sortBy?: 'name' | 'country' | 'vintage' | 'status' | 'createdAt';

    @ApiPropertyOptional({ enum: ['asc', 'desc'] })
    @IsOptional()
    @IsIn(['asc', 'desc'])
    sortDir?: 'asc' | 'desc';
}

export interface ProjectRow {
    id: string;
    consensusTimestamp: string;
    dynamicTopicId: string;
    methodologyTopicId: string;
    instanceTopicId: string;
    schemaIri: string;
    projectId: string | null;
    name: string | null;
    description: string | null;
    country: string | null;
    countryCode: string | null;
    region: string | null;
    latitude: string | null;
    longitude: string | null;
    startDate: string | null;
    endDate: string | null;
    vintage: string | null;
    proponentName: string | null;
    status: string | null;
    methodologyTag: string | null;
    sector: string | null;
    category: string | null;
    projectType: string | null;
    rawVc: Record<string, unknown>;
    extras: Record<string, unknown>;
    extractionMeta: Record<string, unknown>;
    createdAt: Date;
    updatedAt: Date;
}

export class ProjectResponseDto {
    @ApiProperty()
    id: string;

    @ApiProperty()
    network: string;

    @ApiProperty()
    consensusTimestamp: string;

    @ApiProperty()
    dynamicTopicId: string;

    @ApiProperty()
    methodologyTopicId: string;

    @ApiProperty()
    instanceTopicId: string;

    @ApiProperty()
    schemaIri: string;

    @ApiProperty({ nullable: true })
    projectId: string | null;

    @ApiProperty({ nullable: true })
    name: string | null;

    @ApiProperty({ nullable: true })
    description: string | null;

    @ApiProperty({ nullable: true })
    country: string | null;

    @ApiProperty({ nullable: true })
    countryCode: string | null;

    @ApiProperty({ nullable: true })
    region: string | null;

    @ApiProperty({ nullable: true })
    latitude: number | null;

    @ApiProperty({ nullable: true })
    longitude: number | null;

    @ApiProperty({ nullable: true })
    startDate: string | null;

    @ApiProperty({ nullable: true })
    endDate: string | null;

    @ApiProperty({ nullable: true })
    vintage: string | null;

    @ApiProperty({ nullable: true })
    proponentName: string | null;

    @ApiProperty({ nullable: true })
    status: string | null;

    @ApiProperty({ nullable: true })
    methodologyTag: string | null;

    @ApiProperty({ nullable: true })
    sector: string | null;

    @ApiProperty({ nullable: true })
    category: string | null;

    @ApiProperty({ nullable: true })
    projectType: string | null;

    @ApiProperty({ type: 'object', additionalProperties: true })
    extras: Record<string, unknown>;

    @ApiProperty({ type: 'object', additionalProperties: true })
    extractionMeta: Record<string, unknown>;

    @ApiProperty()
    createdAt: Date;

    @ApiProperty()
    updatedAt: Date;

    static fromRow(row: ProjectRow, network: string, includeRaw = false): ProjectResponseDto & { rawVc?: Record<string, unknown> } {
        const dto: ProjectResponseDto & { rawVc?: Record<string, unknown> } = {
            id: row.id,
            network,
            consensusTimestamp: row.consensusTimestamp,
            dynamicTopicId: row.dynamicTopicId,
            methodologyTopicId: row.methodologyTopicId,
            instanceTopicId: row.instanceTopicId,
            schemaIri: row.schemaIri,
            projectId: row.projectId,
            name: row.name,
            description: row.description,
            country: row.country,
            countryCode: row.countryCode,
            region: row.region,
            latitude: row.latitude !== null ? parseFloat(row.latitude) : null,
            longitude: row.longitude !== null ? parseFloat(row.longitude) : null,
            startDate: row.startDate,
            endDate: row.endDate,
            vintage: row.vintage,
            proponentName: row.proponentName,
            status: row.status,
            methodologyTag: row.methodologyTag,
            sector: row.sector,
            category: row.category,
            projectType: row.projectType,
            extras: row.extras ?? {},
            extractionMeta: row.extractionMeta ?? {},
            createdAt: row.createdAt,
            updatedAt: row.updatedAt,
        };
        if (includeRaw) dto.rawVc = row.rawVc;
        return dto;
    }
}

export class PaginatedProjectsDto {
    @ApiProperty({ type: [ProjectResponseDto] })
    data: ProjectResponseDto[];

    @ApiProperty()
    meta: { page: number; limit: number; total: number; totalPages: number };
}

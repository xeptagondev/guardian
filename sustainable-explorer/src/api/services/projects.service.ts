import { Injectable, NotFoundException } from '@nestjs/common';
import { NetworkDataSourceRegistry } from '../database/network-datasource.registry';
import { PaginatedResponse } from '../dto/pagination.dto';
import { ProjectQueryDto, ProjectResponseDto } from '../dto/project.dto';
import { PgProjectRepository } from '../repositories/pg-project.repository';
import { ProjectRepository } from '../repositories/project.repository';

@Injectable()
export class ProjectsService {
    constructor(private readonly dataSources: NetworkDataSourceRegistry) {}

    async listByMethodology(
        network: string,
        methodologyTopicId: string,
        query: ProjectQueryDto,
    ): Promise<PaginatedResponse<ProjectResponseDto>> {
        const repo = this.repo(network);
        const page = query.page ?? 1;
        const limit = query.limit ?? 20;

        const result = await repo.listByMethodology(methodologyTopicId, {
            page, limit,
            search: query.search,
            country: query.country,
            status: query.status,
            vintage: query.vintage,
            sector: query.sector,
            projectType: query.projectType,
            sortBy: query.sortBy,
            sortDir: query.sortDir,
        });

        const data = result.rows.map((row) => ProjectResponseDto.fromRow(row, network));
        return new PaginatedResponse(data, result.total, page, limit);
    }

    async listAll(
        network: string,
        query: ProjectQueryDto,
    ): Promise<PaginatedResponse<ProjectResponseDto>> {
        const repo = this.repo(network);
        const page = query.page ?? 1;
        const limit = query.limit ?? 20;

        const result = await repo.listAll({
            page, limit,
            search: query.search,
            country: query.country,
            status: query.status,
            vintage: query.vintage,
            sector: query.sector,
            projectType: query.projectType,
            methodologyTopicId: query.methodologyTopicId,
            sortBy: query.sortBy,
            sortDir: query.sortDir,
        });

        const data = result.rows.map((row) => ProjectResponseDto.fromRow(row, network));
        return new PaginatedResponse(data, result.total, page, limit);
    }

    async findById(network: string, id: string): Promise<ProjectResponseDto & { rawVc?: Record<string, unknown> }> {
        const repo = this.repo(network);
        const row = await repo.findById(id);
        if (!row) throw new NotFoundException(`Project ${id} not found on ${network}`);
        return ProjectResponseDto.fromRow(row, network, true);
    }

    private repo(network: string): ProjectRepository {
        return new PgProjectRepository(this.dataSources.getDataSource(network));
    }
}

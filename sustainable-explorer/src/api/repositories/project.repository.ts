import { ProjectRow } from '../dto/project.dto';

export interface ProjectListQuery {
    page: number;
    limit: number;
    search?: string;
    country?: string;
    status?: string;
    vintage?: string;
    sector?: string;
    projectType?: string;
    methodologyTopicId?: string;
    sortBy?: 'name' | 'country' | 'vintage' | 'status' | 'createdAt';
    sortDir?: 'asc' | 'desc';
}

export interface ProjectListResult {
    rows: ProjectRow[];
    total: number;
}

export abstract class ProjectRepository {
    abstract listByMethodology(
        methodologyTopicId: string,
        query: ProjectListQuery,
    ): Promise<ProjectListResult>;

    abstract listAll(query: ProjectListQuery): Promise<ProjectListResult>;

    abstract findById(id: string): Promise<ProjectRow | null>;
}

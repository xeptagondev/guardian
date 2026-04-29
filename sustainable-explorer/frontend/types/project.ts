export interface ProjectDto {
    id: string;
    network: string;
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
    latitude: number | null;
    longitude: number | null;
    startDate: string | null;
    endDate: string | null;
    vintage: string | null;
    proponentName: string | null;
    status: string | null;
    methodologyTag: string | null;
    sector: string | null;
    category: string | null;
    projectType: string | null;
    extras: Record<string, unknown>;
    extractionMeta: Record<string, unknown>;
    rawVc?: Record<string, unknown>;
    createdAt: string;
    updatedAt: string;
}

export interface ProjectsMeta {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
}

export interface ProjectsResponse {
    data: ProjectDto[];
    meta: ProjectsMeta;
}

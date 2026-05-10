export interface IssuanceListRow {
    mintConsensusTimestamp: string;
    tokenId: string | null;
    tokenName: string | null;
    symbol: string | null;
    tokenType: string | null;
    amount: number;
    mintDate: string | null;
    projectId: string | null;
    projectName: string | null;
    methodology: string | null;
    methodologyId: string | null;
    country: string | null;
    registry: string | null;
    linkMethod: string;
}

export interface IssuanceListQuery {
    page: number;
    limit: number;
    search?: string;
    sortBy?: string;
    sortDir?: 'asc' | 'desc';
    dateFrom?: string;
    dateTo?: string;
    tokenType?: string;
    projectId?: string;
}

export interface IssuanceListResult {
    rows: IssuanceListRow[];
    total: number;
}

export abstract class IssuanceRepository {
    abstract findAll(query: IssuanceListQuery): Promise<IssuanceListResult>;
}

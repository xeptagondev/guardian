export interface PolicyBlock {
    id?: string;
    tag?: string;
    blockType: string;
    permissions?: string[];
    children?: PolicyBlock[];
    dependencies?: string[];
    [key: string]: unknown;
}

export type PolicyStatus = 'PENDING' | 'DECODED' | 'FAILED';

export interface PolicyDetailDto {
    instanceTopicId: string;
    policyTopicId: string;
    name: string | null;
    version: string | null;
    uuid: string | null;
    status: PolicyStatus;
    cid: string | null;
    messageTimestamp: string | null;
    config: PolicyBlock | null;
    metadata: Record<string, unknown>;
    schemas: Array<Record<string, unknown>>;
    tokens: Array<Record<string, unknown>>;
}

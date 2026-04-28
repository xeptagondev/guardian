export interface PolicyRow {
    instanceTopicId: string;
    policyTopicId: string;
    name: string | null;
    version: string | null;
    uuid: string | null;
    status: 'PENDING' | 'DECODED' | 'FAILED';
    cid: string | null;
    messageTimestamp: string | null;
    policyJson: Record<string, unknown> | null;
    schemas: Array<Record<string, unknown>> | null;
    tokens: Array<Record<string, unknown>> | null;
}

export abstract class PolicyDetailRepository {
    abstract findByInstanceTopicId(instanceTopicId: string): Promise<PolicyRow | null>;
}

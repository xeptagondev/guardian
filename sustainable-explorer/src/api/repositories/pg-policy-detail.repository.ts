import { DataSource } from 'typeorm';
import { PolicyDetailRepository, PolicyRow } from './policy-detail.repository';

export class PgPolicyDetailRepository extends PolicyDetailRepository {
    constructor(private readonly dataSource: DataSource) {
        super();
    }

    async findByInstanceTopicId(instanceTopicId: string): Promise<PolicyRow | null> {
        const rows: PolicyRow[] = await this.dataSource.query(
            `
            SELECT
                "instanceTopicId",
                "policyTopicId",
                name,
                version,
                uuid,
                status,
                cid,
                "messageTimestamp",
                "policyJson",
                schemas,
                tokens
            FROM policy
            WHERE "instanceTopicId" = $1
            LIMIT 1
            `,
            [instanceTopicId],
        );
        return rows[0] ?? null;
    }
}

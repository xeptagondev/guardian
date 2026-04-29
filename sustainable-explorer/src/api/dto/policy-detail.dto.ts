import { ApiProperty } from '@nestjs/swagger';
import { PolicyRow } from '../repositories/policy-detail.repository';

export class PolicyDetailResponseDto {
    @ApiProperty()
    instanceTopicId: string;

    @ApiProperty()
    policyTopicId: string;

    @ApiProperty({ nullable: true })
    name: string | null;

    @ApiProperty({ nullable: true })
    version: string | null;

    @ApiProperty({ nullable: true })
    uuid: string | null;

    @ApiProperty({ enum: ['PENDING', 'DECODED', 'FAILED'] })
    status: 'PENDING' | 'DECODED' | 'FAILED';

    @ApiProperty({ nullable: true })
    cid: string | null;

    @ApiProperty({ nullable: true })
    messageTimestamp: string | null;

    @ApiProperty({
        nullable: true,
        description: 'Root policy block tree (policyJson.config). Has shape { id, blockType, tag, permissions, children: [...] }.',
        type: 'object',
        additionalProperties: true,
    })
    config: Record<string, unknown> | null;

    @ApiProperty({
        description: 'Top-level policy.json fields (excluding config).',
        type: 'object',
        additionalProperties: true,
    })
    metadata: Record<string, unknown>;

    @ApiProperty({
        description: 'Schemas extracted from the policy ZIP by the policy-ingest worker.',
        type: 'array',
        items: { type: 'object', additionalProperties: true },
    })
    schemas: Array<Record<string, unknown>>;

    @ApiProperty({
        description: 'Token definitions extracted from the policy ZIP.',
        type: 'array',
        items: { type: 'object', additionalProperties: true },
    })
    tokens: Array<Record<string, unknown>>;

    static fromRow(row: PolicyRow, _network: string): PolicyDetailResponseDto {
        const policyJson = row.policyJson ?? null;
        let config: Record<string, unknown> | null = null;
        const metadata: Record<string, unknown> = {};

        if (policyJson && typeof policyJson === 'object') {
            const rawConfig = (policyJson as Record<string, unknown>).config;
            if (rawConfig && typeof rawConfig === 'object' && !Array.isArray(rawConfig)) {
                config = rawConfig as Record<string, unknown>;
            } else if (typeof (policyJson as Record<string, unknown>).blockType === 'string') {
                // Some older archives put the block tree at the root level.
                config = policyJson as Record<string, unknown>;
            }
            for (const [k, v] of Object.entries(policyJson as Record<string, unknown>)) {
                if (k === 'config') continue;
                metadata[k] = v;
            }
        }

        return {
            instanceTopicId: row.instanceTopicId,
            policyTopicId: row.policyTopicId,
            name: row.name,
            version: row.version,
            uuid: row.uuid,
            status: row.status,
            cid: row.cid,
            messageTimestamp: row.messageTimestamp,
            config,
            metadata,
            schemas: Array.isArray(row.schemas) ? row.schemas : [],
            tokens: Array.isArray(row.tokens) ? row.tokens : [],
        };
    }
}

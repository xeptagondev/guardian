import { Injectable, NotFoundException } from '@nestjs/common';
import { NetworkDataSourceRegistry } from '../database/network-datasource.registry';
import { PolicyDetailRepository } from '../repositories/policy-detail.repository';
import { PgPolicyDetailRepository } from '../repositories/pg-policy-detail.repository';
import { PolicyDetailResponseDto } from '../dto/policy-detail.dto';

@Injectable()
export class PolicyDetailService {
    constructor(private readonly dataSources: NetworkDataSourceRegistry) {}

    async findByMethodologyId(network: string, methodologyId: string): Promise<PolicyDetailResponseDto> {
        const repo = this.getRepository(network);
        const row = await repo.findByInstanceTopicId(methodologyId);

        if (!row) {
            throw new NotFoundException(
                `No policy decoded for methodology ${methodologyId} on ${network}`,
            );
        }
        if (row.status !== 'DECODED') {
            throw new NotFoundException(
                `Policy for methodology ${methodologyId} is not yet decoded (status=${row.status})`,
            );
        }

        return PolicyDetailResponseDto.fromRow(row, network);
    }

    private getRepository(network: string): PolicyDetailRepository {
        const ds = this.dataSources.getDataSource(network);
        return new PgPolicyDetailRepository(ds);
    }
}

import { Injectable } from '@nestjs/common';
import { NetworkDataSourceRegistry } from '../database/network-datasource.registry';
import { PgSummaryRepository } from '../repositories/pg-summary.repository';
import { DashboardSummaryDto } from '../dto/summary.dto';

@Injectable()
export class SummaryService {
    constructor(private readonly dataSources: NetworkDataSourceRegistry) {}

    async getDashboardSummary(network: string): Promise<DashboardSummaryDto> {
        const ds = this.dataSources.getDataSource(network);
        const repo = new PgSummaryRepository(ds);
        return repo.getDashboardSummary();
    }
}

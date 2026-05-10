import { Injectable } from '@nestjs/common';
import { IssuanceQueryDto, IssuanceListItemDto, PaginatedIssuancesDto } from '../dto/issuance.dto';
import { PaginatedResponse } from '../dto/pagination.dto';
import { NetworkDataSourceRegistry } from '../database/network-datasource.registry';
import { PgIssuanceRepository } from '../repositories/pg-issuance.repository';

@Injectable()
export class IssuancesService {
    constructor(private readonly dataSources: NetworkDataSourceRegistry) {}

    async findAll(
        network: string,
        query: IssuanceQueryDto,
    ): Promise<PaginatedIssuancesDto> {
        const ds = this.dataSources.getDataSource(network);
        const repo = new PgIssuanceRepository(ds);

        const page = query.page ?? 1;
        const limit = query.limit ?? 20;

        const result = await repo.findAll({
            page,
            limit,
            search: query.search,
            sortBy: query.sortBy,
            sortDir: query.sortDir,
            dateFrom: query.dateFrom,
            dateTo: query.dateTo,
            tokenType: query.tokenType,
            projectId: query.projectId,
        });

        const data = result.rows.map(row => IssuanceListItemDto.fromRow(row));
        return new PaginatedResponse(data, result.total, page, limit) as PaginatedIssuancesDto;
    }
}

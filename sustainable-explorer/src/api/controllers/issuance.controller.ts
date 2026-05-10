import { Controller, Get, Param, Query } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam } from '@nestjs/swagger';
import { IssuancesService } from '../services/issuance.service';
import { IssuanceQueryDto, PaginatedIssuancesDto } from '../dto/issuance.dto';

@ApiTags('issuances')
@Controller('api/v1/:network/issuances')
export class IssuancesController {
    constructor(private readonly issuancesService: IssuancesService) {}

    @Get()
    @ApiOperation({
        summary: 'List Issuances',
        description:
            'Returns a paginated list of all MintToken events linked to projects on the specified network. ' +
            'Supports full-text search across project name and token name, filtering by date range, ' +
            'token type, and project, plus sorting by mint date, amount, or project name.',
    })
    @ApiParam({
        name: 'network',
        enum: ['mainnet', 'testnet', 'previewnet'],
        description: 'Hedera network',
    })
    @ApiResponse({ status: 200, type: PaginatedIssuancesDto })
    @ApiResponse({ status: 404, description: 'Network not configured on this API instance' })
    async findAll(
        @Param('network') network: string,
        @Query() query: IssuanceQueryDto,
    ): Promise<PaginatedIssuancesDto> {
        return this.issuancesService.findAll(network, query);
    }
}

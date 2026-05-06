import { Controller, Get, Param } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiParam, ApiResponse } from '@nestjs/swagger';
import { SummaryService } from '../services/summary.service';
import { DashboardSummaryDto } from '../dto/summary.dto';

@ApiTags('summary')
@Controller('api/v1')
export class SummaryController {
    constructor(private readonly summaryService: SummaryService) {}

    @Get(':network/dashboard-summary')
    @ApiOperation({
        summary: 'Get full dashboard summary',
        description:
            'Returns total issued/retired/active credits, monthly issuance timeline, and per-registry issuance breakdown — all derived from a single optimised query.',
    })
    @ApiParam({
        name: 'network',
        enum: ['mainnet', 'testnet', 'previewnet'],
        description: 'Hedera network',
    })
    @ApiResponse({ status: 200, type: DashboardSummaryDto })
    @ApiResponse({ status: 404, description: 'Network not configured on this API instance' })
    async getDashboardSummary(
        @Param('network') network: string,
    ): Promise<DashboardSummaryDto> {
        return this.summaryService.getDashboardSummary(network);
    }
}

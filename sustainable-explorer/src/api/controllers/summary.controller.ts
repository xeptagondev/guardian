import { Controller, Get, Param } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiParam, ApiResponse } from '@nestjs/swagger';
import { SummaryService } from '../services/summary.service';
import { SummaryResponseDto } from '../dto/summary.dto';

@ApiTags('summary')
@Controller('api/v1')
export class SummaryController {
    constructor(private readonly summaryService: SummaryService) {}

    @Get(':network/summary')
    @ApiOperation({
        summary: 'Get global credit totals',
        description:
            'Returns the total issued, retired, and active credit amounts for the specified Hedera network.',
    })
    @ApiParam({
        name: 'network',
        enum: ['mainnet', 'testnet', 'previewnet'],
        description: 'Hedera network',
    })
    @ApiResponse({ status: 200, type: SummaryResponseDto })
    @ApiResponse({ status: 404, description: 'Network not configured on this API instance' })
    async getSummary(
        @Param('network') network: string,
    ): Promise<SummaryResponseDto> {
        return this.summaryService.getSummary(network);
    }
}

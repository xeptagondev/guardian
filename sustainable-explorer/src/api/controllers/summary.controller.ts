import { Controller, Get, Param } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiParam, ApiResponse } from '@nestjs/swagger';
import { SummaryService } from '../services/summary.service';
import { SummaryResponseDto, TimelinePointDto } from '../dto/summary.dto';

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

    @Get(':network/summary/timeline')
    @ApiOperation({
        summary: 'Get monthly issuance timeline',
        description:
            'Returns per-month MintToken VC totals. Monthly granularity only — callers should aggregate to quarterly/yearly client-side.',
    })
    @ApiParam({
        name: 'network',
        enum: ['mainnet', 'testnet', 'previewnet'],
        description: 'Hedera network',
    })
    @ApiResponse({ status: 200, type: [TimelinePointDto] })
    @ApiResponse({ status: 404, description: 'Network not configured on this API instance' })
    async getTimeline(
        @Param('network') network: string,
    ): Promise<TimelinePointDto[]> {
        return this.summaryService.getTimeline(network);
    }
}

import { Controller, Get, Param } from '@nestjs/common';
import { ApiOperation, ApiParam, ApiResponse, ApiTags } from '@nestjs/swagger';
import { PolicyDetailService } from '../services/policy-detail.service';
import { PolicyDetailResponseDto } from '../dto/policy-detail.dto';

@ApiTags('policy-detail')
@Controller('api/v1/:network/methodologies/:id/policy')
export class PolicyDetailController {
    constructor(private readonly policyDetailService: PolicyDetailService) {}

    @Get()
    @ApiOperation({
        summary: 'Get the decoded policy for a methodology',
        description:
            'Returns the decoded policy.json from the published Instance-Policy ZIP, including the block tree (config), metadata, extracted schemas, and tokens.',
    })
    @ApiParam({
        name: 'network',
        enum: ['mainnet', 'testnet', 'previewnet'],
        description: 'Hedera network',
    })
    @ApiParam({ name: 'id', description: 'Methodology instance topic ID (= policy.instanceTopicId)' })
    @ApiResponse({ status: 200, type: PolicyDetailResponseDto })
    @ApiResponse({ status: 404, description: 'Policy not yet decoded for this methodology' })
    async findByMethodologyId(
        @Param('network') network: string,
        @Param('id') methodologyId: string,
    ): Promise<PolicyDetailResponseDto> {
        return this.policyDetailService.findByMethodologyId(network, methodologyId);
    }
}

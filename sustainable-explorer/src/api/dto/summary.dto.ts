import { ApiProperty } from '@nestjs/swagger';

export class SummaryResponseDto {
    @ApiProperty({ description: 'Total number of credits issued (sum of all MintToken VC amounts)' })
    totalIssued: number;

    @ApiProperty({ description: 'Total number of credits retired (deleted NFT serials)' })
    totalRetired: number;

    @ApiProperty({ description: 'Total active credits (totalIssued - totalRetired)' })
    totalActive: number;
}

import { ApiProperty } from '@nestjs/swagger';

export class TimelinePointDto {
    @ApiProperty({ description: 'ISO year-month string e.g. "2023-01"' })
    period: string;

    @ApiProperty({ description: 'Total MintToken VC amounts summed for this month (raw token units)' })
    totalIssued: number;
}

export class SummaryResponseDto {
    @ApiProperty({ description: 'Total number of credits issued (sum of all MintToken VC amounts)' })
    totalIssued: number;

    @ApiProperty({ description: 'Total number of credits retired (deleted NFT serials)' })
    totalRetired: number;

    @ApiProperty({ description: 'Total active credits (totalIssued - totalRetired)' })
    totalActive: number;
}

import { ApiProperty } from '@nestjs/swagger';

export class TimelinePointDto {
    @ApiProperty({ description: 'ISO year-month string e.g. "2023-01"' })
    period: string;

    @ApiProperty({ description: 'Total MintToken VC amounts summed for this month' })
    totalIssued: number;
}

export class RegistryBreakdownItemDto {
    @ApiProperty({ description: 'Registry display name or DID if name is unavailable' })
    registry: string;

    @ApiProperty({ description: 'Total MintToken VC amounts issued under this registry' })
    totalIssued: number;
}

export class DashboardSummaryDto {
    @ApiProperty({ description: 'Total credits issued (sum of all MintToken VC amounts)' })
    totalIssued: number;

    @ApiProperty({ description: 'Total credits retired (deleted NFT serials)' })
    totalRetired: number;

    @ApiProperty({ description: 'Total active credits (totalIssued - totalRetired)' })
    totalActive: number;

    @ApiProperty({ type: [TimelinePointDto], description: 'Monthly issuance breakdown' })
    timeline: TimelinePointDto[];

    @ApiProperty({ type: [RegistryBreakdownItemDto], description: 'Issuances grouped by registry' })
    registryBreakdown: RegistryBreakdownItemDto[];
}

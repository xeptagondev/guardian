import { IsOptional, IsString } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { PaginationQueryDto, PaginatedResponse } from './pagination.dto';
import { IssuanceListRow } from '../repositories/issuance.repository';

export class IssuanceQueryDto extends PaginationQueryDto {
    @ApiPropertyOptional({ description: 'Filter by mint date from (YYYY-MM-DD inclusive)' })
    @IsOptional()
    @IsString()
    dateFrom?: string;

    @ApiPropertyOptional({ description: 'Filter by mint date to (YYYY-MM-DD inclusive)' })
    @IsOptional()
    @IsString()
    dateTo?: string;

    @ApiPropertyOptional({ description: 'Filter by token type (FUNGIBLE_COMMON or NON_FUNGIBLE_UNIQUE)' })
    @IsOptional()
    @IsString()
    tokenType?: string;

    @ApiPropertyOptional({ description: 'Filter by project source timestamp (exact match)' })
    @IsOptional()
    @IsString()
    projectId?: string;
}

export class IssuanceListItemDto {
    @ApiProperty({ description: 'HCS consensus timestamp of the MintToken VC message' })
    mintConsensusTimestamp: string;

    @ApiProperty({ nullable: true, description: 'Hedera token ID (e.g. 0.0.12345)' })
    tokenId: string | null;

    @ApiProperty({ nullable: true, description: 'Token name from token_cache' })
    tokenName: string | null;

    @ApiProperty({ nullable: true, description: 'Token symbol from token_cache' })
    symbol: string | null;

    @ApiProperty({ nullable: true, description: 'Token type: FUNGIBLE_COMMON or NON_FUNGIBLE_UNIQUE' })
    tokenType: string | null;

    @ApiProperty({ description: 'Credits minted in this event' })
    amount: number;

    @ApiProperty({ nullable: true, description: 'Mint date (YYYY-MM-DD)' })
    mintDate: string | null;

    @ApiProperty({ nullable: true, description: 'sourceTimestamp of the linked project' })
    projectId: string | null;

    @ApiProperty({ nullable: true, description: 'Display name of the linked project' })
    projectName: string | null;

    @ApiProperty({ nullable: true, description: 'Methodology name of the linked project' })
    methodology: string | null;

    @ApiProperty({ nullable: true, description: 'Methodology slug of the linked project' })
    methodologyId: string | null;

    @ApiProperty({ nullable: true, description: 'Country of the linked project' })
    country: string | null;

    @ApiProperty({ nullable: true, description: 'Registry display name' })
    registry: string | null;

    @ApiProperty({ description: 'How this mint was linked to the project: relationship | topic_scope' })
    linkMethod: string;

    static fromRow(row: IssuanceListRow): IssuanceListItemDto {
        return {
            mintConsensusTimestamp: row.mintConsensusTimestamp,
            tokenId: row.tokenId,
            tokenName: row.tokenName,
            symbol: row.symbol,
            tokenType: row.tokenType,
            amount: row.amount,
            mintDate: row.mintDate,
            projectId: row.projectId,
            projectName: row.projectName,
            methodology: row.methodology,
            methodologyId: row.methodologyId,
            country: row.country,
            registry: row.registry,
            linkMethod: row.linkMethod,
        };
    }
}

export class PaginatedIssuancesDto extends PaginatedResponse<IssuanceListItemDto> {}

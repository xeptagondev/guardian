import { Injectable } from '@nestjs/common';
import { RedisService } from '@shared/redis/redis.service';
import { SingleFlightService } from '@shared/single-flight/single-flight.service';
import { createHash } from 'crypto';
import { CreditQueryDto, CreditResponseDto, CreditStatsDto } from '../dto/credit.dto';
import { PaginatedResponse } from '../dto/pagination.dto';
import { NetworkDataSourceRegistry } from '../database/network-datasource.registry';
import { PgCreditRepository } from '../repositories/pg-credit.repository';
import { CreditRepository, CreditRawDetail, CreditListQuery } from '../repositories/credit.repository';

const STATS_CACHE_TTL_SECONDS = 60;

// Longer than the other cache TTLs in this file — the underlying Token/MintToken
// HCS messages are immutable once written. The only thing that can move is the
// project/methodology attribution joined in via project_mint_link, which shifts
// only on an admin re-link/reparse action, so a bounded TTL (rather than a
// permanent cache with no invalidation hook) keeps that eventually consistent.
const RAW_CACHE_TTL_SECONDS = 300;

@Injectable()
export class CreditsService {
    constructor(
        private readonly dataSources: NetworkDataSourceRegistry,
        private readonly redis: RedisService,
        private readonly singleFlight: SingleFlightService,
    ) {}

    async findAll(
        network: string,
        query: CreditQueryDto,
    ): Promise<PaginatedResponse<CreditResponseDto>> {
        const repo = this.getRepository(network);
        const page = query.page ?? 1;
        const limit = query.limit ?? 20;

        const result = await repo.findAll({
            ...this.toFilters(query),
            page,
            limit,
            sortBy: query.sortBy,
            sortDir: query.sortDir,
        });

        const data = result.rows.map(row => CreditResponseDto.fromRow(row, network));
        return new PaginatedResponse(data, result.total, page, limit);
    }

    /**
     * Aggregates over the entire filtered set, so the UI never derives totals
     * from one page.
     *
     * Wrapped in SingleFlightService: on a TTL expiry, N concurrent requests
     * for the same filter set previously each missed the cache and ran this
     * query independently — measured as ~70-80 independent executions per 100
     * concurrent requests, inflating tail latency to 300ms-1.8s as they queued
     * for a DB connection. Single-flight collapses that to one computation,
     * with the rest awaiting its result.
     */
    async findStats(network: string, query: CreditQueryDto): Promise<CreditStatsDto> {
        const filters = this.toFilters(query);
        const cacheKey = `credit-stats:${network}:${createHash('sha1')
            .update(JSON.stringify(filters))
            .digest('hex')}`;

        const cached = await this.redis.getJson<CreditStatsDto>(cacheKey);
        if (cached) return cached;

        return this.singleFlight.run(cacheKey, async () => {
            // Re-check: another request may have populated the cache while
            // this one was waiting to be scheduled onto the event loop.
            const cachedAgain = await this.redis.getJson<CreditStatsDto>(cacheKey);
            if (cachedAgain) return cachedAgain;

            const stats = await this.getRepository(network).findStats({ ...filters, page: 1, limit: 1 });
            await this.redis.setJson(cacheKey, stats, STATS_CACHE_TTL_SECONDS);
            return stats;
        });
    }

    /** Filter fields shared by the list, its count and the stats aggregate. */
    private toFilters(query: CreditQueryDto): Omit<CreditListQuery, 'page' | 'limit'> {
        return {
            search: query.search,
            type: query.type,
            registry: query.registry,
            registryDid: query.registryDid,
            tokenId: query.tokenId,
            projectKey: query.projectKey,
            methodologyId: query.methodologyId,
            linkedOnly: query.linkedOnly,
            retiredOnly: query.retiredOnly,
            supplyMin: query.supplyMin,
            supplyMax: query.supplyMax,
            mintDateFrom: query.mintDateFrom,
            mintDateTo: query.mintDateTo,
        };
    }

    async findRaw(network: string, tokenId: string): Promise<CreditRawDetail | null> {
        const cacheKey = `credit-raw:${network}:${tokenId}`;
        const cached = await this.redis.getJson<CreditRawDetail>(cacheKey);
        if (cached) return cached;

        const repo = this.getRepository(network);
        const detail = await repo.findRaw(tokenId);
        if (!detail) return null;

        await this.redis.setJson(cacheKey, detail, RAW_CACHE_TTL_SECONDS);
        return detail;
    }

    /**
     * Resolves the appropriate CreditRepository for the given network.
     * Currently only PostgreSQL is supported; add a factory here to swap
     * in a different backend implementation.
     */
    private getRepository(network: string): CreditRepository {
        const ds = this.dataSources.getDataSource(network);
        return new PgCreditRepository(ds);
    }
}

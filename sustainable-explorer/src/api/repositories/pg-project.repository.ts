import { DataSource } from 'typeorm';
import {
    ProjectRepository,
    ProjectListQuery,
    ProjectListResult,
} from './project.repository';
import { ProjectRow } from '../dto/project.dto';

const SELECT_COLS = `
    p.id::text AS id,
    p."consensusTimestamp",
    p."dynamicTopicId",
    p."methodologyTopicId",
    p."instanceTopicId",
    p."schemaIri",
    p."projectId",
    p.name,
    p.description,
    p.country,
    p."countryCode",
    p.region,
    p.latitude,
    p.longitude,
    p."startDate",
    p."endDate",
    p.vintage,
    p."proponentName",
    p.status,
    p."methodologyTag",
    p.sector,
    p.category,
    p."projectType",
    p."rawVc",
    p.extras,
    p."extractionMeta",
    p."createdAt",
    p."updatedAt"
`;

const SORTABLE: Record<string, string> = {
    name:       'p.name',
    country:    'p.country',
    vintage:    'p.vintage',
    status:     'p.status',
    createdAt:  'p."createdAt"',
};

export class PgProjectRepository extends ProjectRepository {
    constructor(private readonly dataSource: DataSource) {
        super();
    }

    async listByMethodology(
        methodologyId: string,
        query: ProjectListQuery,
    ): Promise<ProjectListResult> {
        // The route param `:id` matches `business_view.relatedTopicId`, which
        // for a METHODOLOGY row is the *instance* topic. Filter on
        // project.instanceTopicId so the tab scopes to this exact version.
        return this.runList(query, [`p."instanceTopicId" = $1`], [methodologyId]);
    }

    async listAll(query: ProjectListQuery): Promise<ProjectListResult> {
        return this.runList(query, [], []);
    }

    async findById(id: string): Promise<ProjectRow | null> {
        const rows: ProjectRow[] = await this.dataSource.query(
            `SELECT ${SELECT_COLS} FROM project p WHERE p.id = $1 LIMIT 1`,
            [id],
        );
        return rows[0] ?? null;
    }

    /**
     * Shared builder for listAll / listByMethodology — applies the optional
     * filters in a single place so the two callers stay consistent.
     */
    private async runList(
        query: ProjectListQuery,
        baseWhere: string[],
        baseParams: unknown[],
    ): Promise<ProjectListResult> {
        const { page, limit } = query;
        const offset = (page - 1) * limit;

        const where = [...baseWhere];
        const params: unknown[] = [...baseParams];
        const next = () => `$${params.length + 1}`;

        if (query.search) {
            const term = `%${query.search.trim()}%`;
            where.push(
                `(p.name ILIKE ${next()} OR p.description ILIKE $${params.length + 1} OR p."projectId" ILIKE $${params.length + 1})`,
            );
            params.push(term);
        }
        if (query.country) {
            where.push(`LOWER(p.country) = LOWER(${next()})`);
            params.push(query.country);
        }
        if (query.status) {
            where.push(`p.status = ${next()}`);
            params.push(query.status);
        }
        if (query.vintage) {
            where.push(`p.vintage = ${next()}`);
            params.push(query.vintage);
        }
        if (query.sector) {
            where.push(`p.sector = ${next()}`);
            params.push(query.sector);
        }
        if (query.projectType) {
            where.push(`p."projectType" = ${next()}`);
            params.push(query.projectType);
        }
        if (query.methodologyTopicId) {
            where.push(`p."methodologyTopicId" = ${next()}`);
            params.push(query.methodologyTopicId);
        }

        const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

        const sortKey = query.sortBy && SORTABLE[query.sortBy] ? SORTABLE[query.sortBy] : SORTABLE.createdAt;
        const sortDir = query.sortDir === 'asc' ? 'ASC' : 'DESC';
        const orderBy = `${sortKey} ${sortDir} NULLS LAST`;

        const limitParam = `$${params.length + 1}`;
        const offsetParam = `$${params.length + 2}`;

        const rowsSql = `
            SELECT ${SELECT_COLS}
            FROM project p
            ${whereSql}
            ORDER BY ${orderBy}
            LIMIT ${limitParam} OFFSET ${offsetParam}
        `;
        const countSql = `SELECT COUNT(*)::int AS total FROM project p ${whereSql}`;

        const [rows, countResult]: [ProjectRow[], Array<{ total: number }>] = await Promise.all([
            this.dataSource.query(rowsSql, [...params, limit, offset]),
            this.dataSource.query(countSql, params),
        ]);

        return { rows, total: countResult[0]?.total ?? 0 };
    }
}

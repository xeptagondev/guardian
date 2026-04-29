import { Injectable, Logger } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { CANONICAL_PROJECT_FIELDS } from './canonical-fields';
import { resolveVcSchema } from './vc-schema-resolver';
import { CanonicalFieldSpec } from '../matchers/field-matcher.interface';

interface MessageRow {
    consensusTimestamp: string;
    topicId: string;
    documents: Record<string, unknown> | null;
    options: Record<string, unknown> | null;
}

interface ResolutionRow {
    policyTopicId: string;
    schemaUuid: string;
    schemaVersion: string;
    schemaIri: string;
    fieldMapping: Record<string, string> | null;
    matcherName: string | null;
    identifierName: string;
    identifierConfidence: string | null;
}

interface TopicAncestry {
    dynamicTopicId: string;
    instanceTopicId: string;
    methodologyTopicId: string;
}

const CANONICAL_FIELDS_BY_KEY: Map<string, CanonicalFieldSpec> = new Map(
    CANONICAL_PROJECT_FIELDS.map((f) => [f.key, f]),
);

const CANONICAL_KEYS_FOR_PROJECT_TABLE = new Set<string>([
    'projectId', 'name', 'description', 'country', 'countryCode', 'region',
    'latitude', 'longitude', 'startDate', 'endDate', 'vintage',
    'proponentName', 'status',
    'methodologyTag', 'sector', 'category', 'projectType',
]);

/**
 * Reads VC messages in DYNAMIC_TOPICs of decoded policies, looks up the
 * cached project_schema_resolution, applies the field mapping, and upserts
 * a row into `project`. Idempotent on `consensusTimestamp`.
 */
@Injectable()
export class ProjectExtractorService {
    private readonly logger = new Logger(ProjectExtractorService.name);

    constructor(private readonly dataSource: DataSource) {}

    /** Find candidate VC messages and extract any that haven't been processed yet. */
    async extractMissing(limit = 500): Promise<{ extracted: number; skipped: number }> {
        // Project VCs land in two places depending on the methodology:
        //   - DYNAMIC_TOPIC          (e.g. EcoRegistry, Verra — one topic per project)
        //   - INSTANCE_POLICY_TOPIC  (e.g. ISO14064 — VCs directly on the instance topic)
        // Both are scanned; resolveTopicAncestry handles the lookup difference.
        const candidates: MessageRow[] = await this.dataSource.query(
            `SELECT m."consensusTimestamp", m."topicId", m.documents, m.options
             FROM message m
             JOIN topic_cache tc ON tc."topicId" = m."topicId"
                                AND tc."topicType" IN ('DYNAMIC_TOPIC', 'INSTANCE_POLICY_TOPIC')
             WHERE m.type IN ('VC-Document', 'VC')
               AND m.documents IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM project p WHERE p."consensusTimestamp" = m."consensusTimestamp"
               )
             ORDER BY m."consensusTimestamp"
             LIMIT $1`,
            [limit],
        );

        let extracted = 0;
        let skipped = 0;
        for (const row of candidates) {
            const ok = await this.extractOne(row);
            if (ok) extracted += 1;
            else skipped += 1;
        }
        if (candidates.length > 0) {
            this.logger.log(
                `Project extraction: ${extracted} extracted, ${skipped} skipped, ${candidates.length} candidates`,
            );
        }
        return { extracted, skipped };
    }

    private async extractOne(message: MessageRow): Promise<boolean> {
        const resolved = resolveVcSchema(message.documents);
        if (!resolved?.schema) return false;

        const ancestry = await this.resolveTopicAncestry(message.topicId);
        if (!ancestry) return false;

        const resolution = await this.findResolution(
            ancestry.methodologyTopicId,
            resolved.schema.schemaUuid,
            resolved.schema.schemaVersion,
        );
        if (!resolution || !resolution.fieldMapping) return false;

        const cs = resolved.parsed.credentialSubject;
        const canonical = this.applyMapping(cs, resolution.fieldMapping);
        const extras = this.buildExtras(cs, resolution.fieldMapping);

        await this.upsertProject({
            consensusTimestamp: message.consensusTimestamp,
            dynamicTopicId: ancestry.dynamicTopicId,
            methodologyTopicId: ancestry.methodologyTopicId,
            instanceTopicId: ancestry.instanceTopicId,
            schemaIri: resolved.schema.schemaIri,
            ...canonical,
            rawVc: message.documents!,
            extras,
            extractionMeta: {
                identifierName: resolution.identifierName,
                identifierConfidence: resolution.identifierConfidence,
                matcherName: resolution.matcherName,
                resolutionVersion: 1,
            },
        });
        return true;
    }

    /**
     * Resolves a VC's owning topic to its parent policy. Works for VCs that
     * live in DYNAMIC_TOPICs (one project = one topic, parent = instance) or
     * directly in the INSTANCE_POLICY_TOPIC (one topic holds many VCs across
     * projects). The `dynamicTopicId` field on the resulting project row is
     * always the topic that *owned* the VC — either the dynamic child or the
     * instance topic itself.
     */
    private async resolveTopicAncestry(topicId: string): Promise<TopicAncestry | null> {
        const rows: Array<{ instanceTopicId: string; methodologyTopicId: string }> = await this.dataSource.query(
            `SELECT
                p."instanceTopicId"  AS "instanceTopicId",
                p."policyTopicId"    AS "methodologyTopicId"
             FROM topic_cache tc
             JOIN policy p
               ON p.status = 'DECODED'
              AND (
                  (tc."topicType" = 'DYNAMIC_TOPIC'         AND p."instanceTopicId" = tc."policyTopicId")
                  OR
                  (tc."topicType" = 'INSTANCE_POLICY_TOPIC' AND p."instanceTopicId" = tc."topicId")
              )
             WHERE tc."topicId" = $1
               AND tc."topicType" IN ('DYNAMIC_TOPIC', 'INSTANCE_POLICY_TOPIC')
             LIMIT 1`,
            [topicId],
        );
        if (rows.length === 0) return null;
        return {
            dynamicTopicId: topicId,
            instanceTopicId: rows[0].instanceTopicId,
            methodologyTopicId: rows[0].methodologyTopicId,
        };
    }

    private async findResolution(
        policyTopicId: string,
        schemaUuid: string,
        schemaVersion: string,
    ): Promise<ResolutionRow | null> {
        const rows: ResolutionRow[] = await this.dataSource.query(
            `SELECT "policyTopicId","schemaUuid","schemaVersion","schemaIri",
                    "fieldMapping","matcherName","identifierName","identifierConfidence"
             FROM project_schema_resolution
             WHERE "policyTopicId" = $1
               AND "schemaUuid" = $2
               AND "schemaVersion" = $3
               AND "isProjectSchema" = true
             LIMIT 1`,
            [policyTopicId, schemaUuid, schemaVersion],
        );
        return rows[0] ?? null;
    }

    /**
     * Applies the cached path mapping to a credentialSubject. Multi-language
     * variants land in `extras` (computed separately by buildExtras).
     */
    private applyMapping(cs: Record<string, unknown>, mapping: Record<string, string>): {
        projectId: string | null;
        name: string | null;
        description: string | null;
        country: string | null;
        countryCode: string | null;
        region: string | null;
        latitude: string | null;
        longitude: string | null;
        startDate: string | null;
        endDate: string | null;
        vintage: string | null;
        proponentName: string | null;
        status: string | null;
        methodologyTag: string | null;
        sector: string | null;
        category: string | null;
        projectType: string | null;
    } {
        const out: Record<string, string | null> = {
            projectId: null, name: null, description: null,
            country: null, countryCode: null, region: null, latitude: null, longitude: null,
            startDate: null, endDate: null, vintage: null,
            proponentName: null, status: null,
            methodologyTag: null, sector: null, category: null, projectType: null,
        };

        for (const key of CANONICAL_KEYS_FOR_PROJECT_TABLE) {
            const path = mapping[key];
            if (!path) continue;
            const raw = this.readPath(cs, path);
            const spec = CANONICAL_FIELDS_BY_KEY.get(key);
            out[key] = this.coerce(raw, spec?.type ?? 'string');
        }

        return out as ReturnType<ProjectExtractorService['applyMapping']>;
    }

    private buildExtras(
        cs: Record<string, unknown>,
        mapping: Record<string, string>,
    ): Record<string, unknown> {
        const extras: Record<string, unknown> = {};

        // Language variants — keys look like `description__en`, `description__es`.
        const languageGroups: Record<string, Record<string, unknown>> = {};
        const usedSourcePaths = new Set<string>();
        for (const [key, path] of Object.entries(mapping)) {
            usedSourcePaths.add(path);
            const lang = key.includes('__') ? key.split('__')[1] : null;
            if (lang) {
                const baseKey = key.split('__')[0];
                const value = this.readPath(cs, path);
                if (value !== null && value !== undefined) {
                    languageGroups[baseKey] ??= {};
                    languageGroups[baseKey][lang] = value;
                }
            }
        }
        for (const [k, v] of Object.entries(languageGroups)) {
            extras[`${k}_languages`] = v;
        }

        // Anything left in credentialSubject that wasn't mapped → unmapped jsonb.
        // Skip JSON-LD plumbing keys (@id, @type, @context, etc.) and any key
        // already consumed by canonical mapping.
        const usedTopLevel = new Set(
            Object.values(mapping)
                .map((p) => p.split('.')[0])
                .filter((k) => !!k),
        );

        const unmapped: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(cs)) {
            if (k.startsWith('@')) continue;
            if (k === 'id' || k === 'type') continue;
            if (usedTopLevel.has(k)) continue;
            unmapped[k] = v;
        }
        if (Object.keys(unmapped).length > 0) {
            extras.unmapped = unmapped;
        }

        return extras;
    }

    private readPath(obj: Record<string, unknown>, path: string): unknown {
        const segments = path.split('.');
        let cursor: unknown = obj;
        for (const seg of segments) {
            if (cursor === null || cursor === undefined) return undefined;
            if (Array.isArray(cursor)) {
                const idx = parseInt(seg, 10);
                cursor = Number.isNaN(idx) ? undefined : cursor[idx];
            } else if (typeof cursor === 'object') {
                cursor = (cursor as Record<string, unknown>)[seg];
            } else {
                return undefined;
            }
        }
        return cursor;
    }

    private coerce(raw: unknown, type: 'string' | 'number' | 'date' | 'boolean'): string | null {
        if (raw === null || raw === undefined || raw === '') return null;
        switch (type) {
            case 'string':
                return typeof raw === 'string' ? raw.trim() : String(raw);
            case 'number': {
                const n = typeof raw === 'number' ? raw : parseFloat(String(raw));
                return Number.isFinite(n) ? n.toString() : null;
            }
            case 'date': {
                const d = new Date(String(raw));
                return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
            }
            case 'boolean':
                return raw ? 'true' : 'false';
        }
    }

    private async upsertProject(p: {
        consensusTimestamp: string;
        dynamicTopicId: string;
        methodologyTopicId: string;
        instanceTopicId: string;
        schemaIri: string;
        projectId: string | null;
        name: string | null;
        description: string | null;
        country: string | null;
        countryCode: string | null;
        region: string | null;
        latitude: string | null;
        longitude: string | null;
        startDate: string | null;
        endDate: string | null;
        vintage: string | null;
        proponentName: string | null;
        status: string | null;
        methodologyTag: string | null;
        sector: string | null;
        category: string | null;
        projectType: string | null;
        rawVc: Record<string, unknown>;
        extras: Record<string, unknown>;
        extractionMeta: Record<string, unknown>;
    }): Promise<void> {
        await this.dataSource.query(
            `INSERT INTO project (
                "consensusTimestamp","dynamicTopicId","methodologyTopicId","instanceTopicId",
                "schemaIri","projectId",name,description,country,"countryCode",region,
                latitude,longitude,"startDate","endDate",vintage,"proponentName",status,
                "methodologyTag",sector,category,"projectType",
                "rawVc",extras,"extractionMeta","createdAt","updatedAt"
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,NOW(),NOW())
            ON CONFLICT ("consensusTimestamp") DO UPDATE SET
                "dynamicTopicId"     = EXCLUDED."dynamicTopicId",
                "methodologyTopicId" = EXCLUDED."methodologyTopicId",
                "instanceTopicId"    = EXCLUDED."instanceTopicId",
                "schemaIri"          = EXCLUDED."schemaIri",
                "projectId"          = EXCLUDED."projectId",
                name                 = EXCLUDED.name,
                description          = EXCLUDED.description,
                country              = EXCLUDED.country,
                "countryCode"        = EXCLUDED."countryCode",
                region               = EXCLUDED.region,
                latitude             = EXCLUDED.latitude,
                longitude            = EXCLUDED.longitude,
                "startDate"          = EXCLUDED."startDate",
                "endDate"            = EXCLUDED."endDate",
                vintage              = EXCLUDED.vintage,
                "proponentName"      = EXCLUDED."proponentName",
                status               = EXCLUDED.status,
                "methodologyTag"     = EXCLUDED."methodologyTag",
                sector               = EXCLUDED.sector,
                category             = EXCLUDED.category,
                "projectType"        = EXCLUDED."projectType",
                "rawVc"              = EXCLUDED."rawVc",
                extras               = EXCLUDED.extras,
                "extractionMeta"     = EXCLUDED."extractionMeta",
                "updatedAt"          = NOW()`,
            [
                p.consensusTimestamp, p.dynamicTopicId, p.methodologyTopicId, p.instanceTopicId,
                p.schemaIri, p.projectId, p.name, p.description, p.country, p.countryCode, p.region,
                p.latitude, p.longitude, p.startDate, p.endDate, p.vintage, p.proponentName, p.status,
                p.methodologyTag, p.sector, p.category, p.projectType,
                JSON.stringify(p.rawVc), JSON.stringify(p.extras), JSON.stringify(p.extractionMeta),
            ],
        );
    }
}

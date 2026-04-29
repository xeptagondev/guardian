import { Injectable, Logger } from '@nestjs/common';
import { DataSource } from 'typeorm';
import {
    DecodedPolicy,
    PolicyClassifiedSchema,
    PolicyBlock,
} from './types';
import { ProjectSchemaIdentifier } from '../matchers/project-schema-identifier.interface';
import { RegexProjectSchemaIdentifier } from '../matchers/regex-project-schema-identifier';
import { FieldMatcher, FieldMapping } from '../matchers/field-matcher.interface';
import { RegexFieldMatcher } from '../matchers/regex-field-matcher';
import { CANONICAL_PROJECT_FIELDS } from './canonical-fields';
import { flattenSchemaProperties } from './schema-field-flattener';

interface PolicyRow {
    instanceTopicId: string;
    policyTopicId: string;
    name: string | null;
    version: string | null;
    uuid: string | null;
    cid: string | null;
    messageTimestamp: string | null;
    policyJson: Record<string, unknown> | null;
    schemas: PolicyClassifiedSchema[] | null;
    tokens: Array<Record<string, unknown>> | null;
}

interface SchemaFileRow {
    schemaId: string;
    schemaVersion: string;
    name: string | null;
    description: string | null;
    schemaFile: string;
    document: Record<string, unknown> | null;
}

/**
 * Runs the project-schema identifier and field matcher for a decoded
 * policy and persists the results into `project_schema_resolution`.
 *
 * Idempotent: re-running for the same (policyTopicId, schemaUuid,
 * schemaVersion) overwrites the row UNLESS `isManual = true`.
 */
@Injectable()
export class ProjectSchemaResolverService {
    private readonly logger = new Logger(ProjectSchemaResolverService.name);

    private readonly identifier: ProjectSchemaIdentifier = new RegexProjectSchemaIdentifier();
    private readonly fieldMatcher: FieldMatcher = new RegexFieldMatcher();

    constructor(private readonly dataSource: DataSource) {}

    /** Resolves a policy by its instance topic. Returns the IRIs identified as project schemas. */
    async resolveByInstanceTopic(instanceTopicId: string): Promise<string[]> {
        const policy = await this.loadPolicy(instanceTopicId);
        if (!policy) {
            this.logger.debug(`No DECODED policy for instance ${instanceTopicId}`);
            return [];
        }

        const schemaFiles = await this.loadSchemaFiles(policy.policyTopicId);
        const decoded = this.assembleDecodedPolicy(policy, schemaFiles);

        const candidates = await this.identifier.identify(decoded, {
            methodologyName: decoded.name,
        });

        if (candidates.length === 0) {
            this.logger.warn(`Identifier produced no candidates for policy ${policy.policyTopicId}`);
            return [];
        }

        const winners = candidates.filter(
            (c) => c.confidence >= RegexProjectSchemaIdentifier.THRESHOLD,
        );
        if (winners.length === 0) {
            this.logger.warn(
                `No candidate cleared threshold for policy ${policy.policyTopicId} ` +
                `(top=${candidates[0].confidence})`,
            );
        }

        const winnerIris = new Set(winners.map((w) => w.schemaIri));
        const projectSchemaIris: string[] = [];

        // Persist a row for EVERY candidate (even non-winners) so admins can
        // inspect what the identifier saw and override if needed.
        for (const candidate of candidates) {
            const isWinner = winnerIris.has(candidate.schemaIri);

            // Compute field mapping only for winners — saves work and keeps
            // matcherMeta meaningful (no mapping for non-project schemas).
            let fieldMapping: Record<string, string> | null = null;
            let matcherMeta: Record<string, unknown> | null = null;
            let matcherName: string | null = null;

            if (isWinner) {
                const file = schemaFiles.find((f) => f.schemaId === candidate.schemaUuid);
                if (file?.document) {
                    // Build a $ref resolver over the package's schemas so the
                    // flattener can follow Locations / Coordinates / etc.
                    const refResolver = this.buildRefResolver(schemaFiles);
                    const fields = flattenSchemaProperties(file.document, '', 0, refResolver);
                    const mappings = await this.fieldMatcher.match(
                        CANONICAL_PROJECT_FIELDS,
                        fields,
                        {
                            methodologyName: decoded.name,
                            schemaName: candidate.schemaName,
                            schemaIri: candidate.schemaIri,
                            role: this.findRole(decoded, candidate.schemaIri),
                            blockTags: candidate.sourceBlockTags,
                        },
                    );
                    fieldMapping = this.buildPathMapping(mappings);
                    matcherMeta = this.buildMatcherMeta(mappings, fields.length);
                    matcherName = this.fieldMatcher.name;
                    projectSchemaIris.push(candidate.schemaIri);
                } else {
                    this.logger.warn(
                        `Winner schema ${candidate.schemaIri} has no document — skipping field mapping`,
                    );
                }
            }

            await this.upsertResolution({
                policyTopicId: policy.policyTopicId,
                schemaUuid: candidate.schemaUuid,
                schemaVersion: candidate.schemaVersion,
                schemaIri: candidate.schemaIri,
                schemaName: candidate.schemaName,
                isProjectSchema: isWinner,
                identifierName: candidate.identifierName,
                identifierConfidence: candidate.confidence,
                candidates: [candidate as unknown as Record<string, unknown>],
                fieldMapping,
                matcherName,
                matcherMeta,
            });
        }

        this.logger.log(
            `Policy ${policy.policyTopicId}: identified ${winners.length}/${candidates.length} project schema(s)`,
        );
        return projectSchemaIris;
    }

    /** Re-resolves all DECODED policies that don't yet have any resolution row. */
    async resolveMissing(): Promise<number> {
        const rows: Array<{ instanceTopicId: string }> = await this.dataSource.query(
            `SELECT p."instanceTopicId"
             FROM policy p
             WHERE p.status = 'DECODED'
               AND NOT EXISTS (
                   SELECT 1 FROM project_schema_resolution r
                   WHERE r."policyTopicId" = p."policyTopicId"
               )
             LIMIT 100`,
        );
        let resolvedCount = 0;
        for (const r of rows) {
            const iris = await this.resolveByInstanceTopic(r.instanceTopicId);
            if (iris.length > 0) resolvedCount += 1;
        }
        return resolvedCount;
    }

    private async loadPolicy(instanceTopicId: string): Promise<PolicyRow | null> {
        const rows: PolicyRow[] = await this.dataSource.query(
            `SELECT
                "instanceTopicId", "policyTopicId", name, version, uuid,
                cid, "messageTimestamp", "policyJson", schemas, tokens
             FROM policy
             WHERE "instanceTopicId" = $1 AND status = 'DECODED'
             LIMIT 1`,
            [instanceTopicId],
        );
        return rows[0] ?? null;
    }

    private async loadSchemaFiles(policyTopicId: string): Promise<SchemaFileRow[]> {
        return await this.dataSource.query(
            `SELECT "schemaId", "schemaVersion", name, description, "schemaFile", document
             FROM policy_schema
             WHERE "policyTopicId" = $1`,
            [policyTopicId],
        );
    }

    private assembleDecodedPolicy(policy: PolicyRow, schemaFiles: SchemaFileRow[]): DecodedPolicy {
        const policyJson = policy.policyJson ?? {};
        const config = (policyJson as Record<string, unknown>).config;
        const rootBlock: PolicyBlock | null =
            config && typeof config === 'object' && !Array.isArray(config)
                ? (config as PolicyBlock)
                : (typeof (policyJson as Record<string, unknown>).blockType === 'string'
                    ? (policyJson as PolicyBlock)
                    : null);

        return {
            instanceTopicId: policy.instanceTopicId,
            policyTopicId: policy.policyTopicId,
            name: policy.name,
            version: policy.version,
            uuid: policy.uuid,
            cid: policy.cid,
            messageTimestamp: policy.messageTimestamp,
            config: rootBlock,
            classifiedSchemas: Array.isArray(policy.schemas) ? policy.schemas : [],
            tokens: Array.isArray(policy.tokens) ? policy.tokens : [],
            schemaFiles,
        };
    }

    /**
     * Returns a SchemaRefResolver bound to the policy's `policy_schema` rows.
     * Looks up by `<uuid>&<version>` regardless of `#` prefix or case.
     */
    private buildRefResolver(schemaFiles: SchemaFileRow[]): (refIri: string) => Record<string, unknown> | null {
        const byKey = new Map<string, Record<string, unknown>>();
        for (const f of schemaFiles) {
            if (!f.document) continue;
            const key = `${(f.schemaId ?? '').toLowerCase()}&${f.schemaVersion ?? ''}`;
            byKey.set(key, f.document);
        }
        return (refIri: string) => {
            const cleaned = refIri.replace(/^#/, '');
            const [uuid, version] = cleaned.split('&');
            if (!uuid || !version) return null;
            return byKey.get(`${uuid.toLowerCase()}&${version}`) ?? null;
        };
    }

    private findRole(policy: DecodedPolicy, iri: string): string | null {
        const norm = iri.replace(/^#/, '').toLowerCase();
        for (const s of policy.classifiedSchemas) {
            if (s.iri.replace(/^#/, '').toLowerCase() === norm) return s.role;
        }
        return null;
    }

    private buildPathMapping(mappings: FieldMapping[]): Record<string, string> {
        const out: Record<string, string> = {};
        for (const m of mappings) {
            out[m.canonicalKey] = m.sourceField.path;
            if (m.languageVariants) {
                for (const [lang, f] of Object.entries(m.languageVariants)) {
                    out[`${m.canonicalKey}__${lang}`] = f.path;
                }
            }
        }
        return out;
    }

    private buildMatcherMeta(mappings: FieldMapping[], totalFields: number): Record<string, unknown> {
        return {
            mappedFields: mappings.length,
            totalFields,
            fields: mappings.map((m) => ({
                canonicalKey: m.canonicalKey,
                sourcePath: m.sourceField.path,
                confidence: m.confidence,
                rationale: m.rationale,
                languages: m.languageVariants ? Object.keys(m.languageVariants) : [],
            })),
        };
    }

    private async upsertResolution(row: {
        policyTopicId: string;
        schemaUuid: string;
        schemaVersion: string;
        schemaIri: string;
        schemaName: string | null;
        isProjectSchema: boolean;
        identifierName: string;
        identifierConfidence: number;
        candidates: Array<Record<string, unknown>>;
        fieldMapping: Record<string, string> | null;
        matcherName: string | null;
        matcherMeta: Record<string, unknown> | null;
    }): Promise<void> {
        await this.dataSource.query(
            `INSERT INTO project_schema_resolution (
                "policyTopicId","schemaUuid","schemaVersion","schemaIri","schemaName",
                "isProjectSchema","identifierName","identifierConfidence","candidates",
                "fieldMapping","matcherName","matcherMeta","isManual",
                "createdAt","updatedAt"
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,false,NOW(),NOW())
            ON CONFLICT ("policyTopicId","schemaUuid","schemaVersion") DO UPDATE SET
                "schemaIri"            = EXCLUDED."schemaIri",
                "schemaName"           = EXCLUDED."schemaName",
                "isProjectSchema"      = CASE WHEN project_schema_resolution."isManual" THEN project_schema_resolution."isProjectSchema" ELSE EXCLUDED."isProjectSchema" END,
                "identifierName"       = EXCLUDED."identifierName",
                "identifierConfidence" = EXCLUDED."identifierConfidence",
                "candidates"           = EXCLUDED."candidates",
                "fieldMapping"         = CASE WHEN project_schema_resolution."isManual" THEN project_schema_resolution."fieldMapping" ELSE EXCLUDED."fieldMapping" END,
                "matcherName"          = EXCLUDED."matcherName",
                "matcherMeta"          = EXCLUDED."matcherMeta",
                "updatedAt"            = NOW()`,
            [
                row.policyTopicId,
                row.schemaUuid,
                row.schemaVersion,
                row.schemaIri,
                row.schemaName,
                row.isProjectSchema,
                row.identifierName,
                row.identifierConfidence,
                JSON.stringify(row.candidates),
                row.fieldMapping ? JSON.stringify(row.fieldMapping) : null,
                row.matcherName,
                row.matcherMeta ? JSON.stringify(row.matcherMeta) : null,
            ],
        );
    }
}

import { DecodedPolicy, PolicyBlock, PolicyClassifiedSchema } from '../project-extraction/types';
import {
    IdentifyContext,
    ProjectSchemaCandidate,
    ProjectSchemaIdentifier,
} from './project-schema-identifier.interface';

/**
 * Regex patterns that identify a "project" semantically inside a Guardian
 * policy — applied to block tags and to schema names. Order doesn't matter
 * (any match scores), but more specific patterns are listed first for
 * readability.
 */
const PROJECT_TAG_PATTERNS: RegExp[] = [
    /(^|[_-])(new[_-]?)?project(s)?([_-]|$)/i,    // rvcdb_new_project, cb_projects, project_data
    /(^|[_-])site([_-]|$)/i,                       // site, site_info
    /create[_-].*project/i,
    /add[_-].*project/i,
];

const PROJECT_NAME_PATTERNS: RegExp[] = [
    /\bproject\b/i,
    /\bsite\b/i,
];

/**
 * Block types that *emit* VCs (i.e. the user submits a form, producing a VC).
 * Documents-source blocks DISPLAY existing VCs and never create new ones, so
 * they're excluded.
 */
const VC_PRODUCING_BLOCK_TYPES = new Set<string>([
    'requestVcDocumentBlock',
]);

/**
 * Roles assigned by policy-ingest's heuristic classifier (see
 * `policy-ingest.processor.ts: classifySchemaRole`). A subset of these
 * are "project-like".
 */
const PROJECT_ROLES = new Set<string>(['PROJECT_INFO', 'SITE']);

interface CandidateAccumulator {
    schemaIri: string;
    blockTagsWithScores: Array<{ tag: string; score: number; rationale: string[] }>;
}

export class RegexProjectSchemaIdentifier implements ProjectSchemaIdentifier {
    public readonly name = 'regex-v1';

    /** Confidence cap; signals can stack up to but not beyond 1.0. */
    private static readonly MAX_SCORE = 1.0;

    /** Below this confidence, callers should not treat the candidate as a project schema. */
    public static readonly THRESHOLD = 0.4;

    async identify(policy: DecodedPolicy, _ctx: IdentifyContext): Promise<ProjectSchemaCandidate[]> {
        if (!policy.config) return [];

        // 1. Walk the block tree, collect every VC-producing block per schema.
        const accumulators = new Map<string, CandidateAccumulator>();
        let firstRequestBlockSchema: string | null = null;

        const walk = (block: PolicyBlock, ancestorTags: string[]): void => {
            const tag = block.tag ?? '';
            const isVcProducing = VC_PRODUCING_BLOCK_TYPES.has(block.blockType);
            const schemaIri = typeof block.schema === 'string' ? block.schema.trim() : '';

            if (isVcProducing && schemaIri) {
                if (firstRequestBlockSchema === null) firstRequestBlockSchema = schemaIri;
                this.addCandidate(accumulators, schemaIri, tag, ancestorTags);
            }

            const children = Array.isArray(block.children) ? block.children : [];
            const nextAncestors = tag ? [...ancestorTags, tag] : ancestorTags;
            for (const child of children) walk(child, nextAncestors);
        };
        walk(policy.config, []);

        // 2. Score each candidate schema by combining block-tag signals,
        //    schema-name signals, and policy-ingest's role classification.
        const candidates: ProjectSchemaCandidate[] = [];
        for (const [schemaIri, acc] of accumulators) {
            const classified = this.findClassifiedSchema(policy, schemaIri);
            const schemaName = this.resolveSchemaName(policy, schemaIri, classified);
            const role = classified?.role ?? null;

            const bestBlock = acc.blockTagsWithScores
                .slice()
                .sort((a, b) => b.score - a.score)[0];
            let score = bestBlock.score;
            const rationaleParts: string[] = [...bestBlock.rationale];

            if (schemaName && this.matchesAny(schemaName, PROJECT_NAME_PATTERNS)) {
                score += 0.15;
                rationaleParts.push(`schema name "${schemaName}" matches project pattern (+0.15)`);
            }
            if (role && PROJECT_ROLES.has(role)) {
                const bonus = role === 'PROJECT_INFO' ? 0.3 : 0.2;
                score += bonus;
                rationaleParts.push(`schema role=${role} (+${bonus})`);
            }
            if (firstRequestBlockSchema === schemaIri) {
                score += 0.1;
                rationaleParts.push('first VC-producing block in workflow (+0.1)');
            }

            score = Math.min(score, RegexProjectSchemaIdentifier.MAX_SCORE);

            const { uuid, version } = this.parseIri(schemaIri);
            candidates.push({
                schemaIri,
                schemaUuid: uuid,
                schemaVersion: version,
                schemaName,
                confidence: Number(score.toFixed(3)),
                rationale: rationaleParts.join('; '),
                sourceBlockTags: acc.blockTagsWithScores.map((b) => b.tag).filter(Boolean),
                identifierName: this.name,
            });
        }

        candidates.sort((a, b) => b.confidence - a.confidence);
        return candidates;
    }

    private addCandidate(
        accumulators: Map<string, CandidateAccumulator>,
        schemaIri: string,
        tag: string,
        ancestorTags: string[],
    ): void {
        const acc = accumulators.get(schemaIri) ?? { schemaIri, blockTagsWithScores: [] };

        let score = 0;
        const rationale: string[] = [];

        if (tag && this.matchesAny(tag, PROJECT_TAG_PATTERNS)) {
            score += 0.5;
            rationale.push(`block tag "${tag}" matches project pattern (+0.5)`);
        }

        const matchingAncestor = ancestorTags
            .slice()
            .reverse()
            .find((t) => this.matchesAny(t, PROJECT_TAG_PATTERNS));
        if (matchingAncestor) {
            score += 0.2;
            rationale.push(`ancestor "${matchingAncestor}" matches project pattern (+0.2)`);
        }

        // No project signals on this block at all — still record so we can
        // attribute the schema to its source blocks for the rationale, but
        // don't grant a positive score.
        if (score === 0 && rationale.length === 0) {
            rationale.push(`block "${tag || '<untagged>'}" referenced this schema (no project signal)`);
        }

        acc.blockTagsWithScores.push({ tag, score, rationale });
        accumulators.set(schemaIri, acc);
    }

    private matchesAny(value: string, patterns: RegExp[]): boolean {
        return patterns.some((p) => p.test(value));
    }

    private findClassifiedSchema(policy: DecodedPolicy, iri: string): PolicyClassifiedSchema | null {
        const norm = this.normalizeIri(iri);
        for (const s of policy.classifiedSchemas) {
            if (this.normalizeIri(s.iri) === norm) return s;
        }
        return null;
    }

    private resolveSchemaName(
        policy: DecodedPolicy,
        iri: string,
        classified: PolicyClassifiedSchema | null,
    ): string | null {
        if (classified?.name) return classified.name;
        const { uuid } = this.parseIri(iri);
        const file = policy.schemaFiles.find((f) => f.schemaId === uuid);
        return file?.name ?? null;
    }

    private normalizeIri(iri: string): string {
        return iri.replace(/^#/, '').toLowerCase().trim();
    }

    private parseIri(iri: string): { uuid: string; version: string } {
        const cleaned = iri.replace(/^#/, '');
        const [uuid, version] = cleaned.split('&');
        return { uuid: uuid ?? '', version: version ?? '' };
    }
}

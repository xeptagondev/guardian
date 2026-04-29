import {
    CanonicalFieldSpec,
    FieldMapping,
    FieldMatcher,
    MatchContext,
    SchemaField,
} from './field-matcher.interface';

interface ScoredCandidate {
    field: SchemaField;
    score: number;
    rationale: string[];
}

/** Regex extracting a trailing language tag like `_en`, `-fr`, `En`, `_pt_BR`. */
const LANGUAGE_TAG_RE = /(?:[_-](?<lang>[a-z]{2})(?:[_-](?<region>[A-Z]{2}))?|(?<langCamel>[A-Z][a-z]))$/;

/**
 * Default scoring weights — tuned empirically on the four sample policies in
 * sample_data/decoded-policies-sample.json. Increase the bonuses if you find
 * the matcher missing legitimate matches; lower the threshold cautiously.
 */
const WEIGHTS = {
    NAME_REGEX_HIT: 0.7,
    DESCRIPTION_REGEX_HIT: 0.1,
    TYPE_AGREES: 0.15,
    READONLY_BONUS: 0.05,            // readOnly fields are usually identity-bearing
    BLOCK_TAG_PROJECT_BONUS: 0.05,
};

const ACCEPT_THRESHOLD = 0.4;

export class RegexFieldMatcher implements FieldMatcher {
    public readonly name = 'regex-v1';

    async match(
        canonical: CanonicalFieldSpec[],
        candidates: SchemaField[],
        ctx: MatchContext,
    ): Promise<FieldMapping[]> {
        const usedFieldPaths = new Set<string>();
        const mappings: FieldMapping[] = [];

        // Process required fields first so identity-bearing matches get
        // dibs over multi-language descriptive fields with the same root.
        const ordered = [...canonical].sort(
            (a, b) => Number(!!b.required) - Number(!!a.required),
        );

        for (const spec of ordered) {
            const scored: ScoredCandidate[] = [];

            for (const field of candidates) {
                if (usedFieldPaths.has(field.path)) continue;
                if (this.isLanguageVariantOf(field.name, spec)) continue;

                const result = this.scoreField(spec, field, ctx);
                if (result.score >= ACCEPT_THRESHOLD) {
                    scored.push({ field, score: result.score, rationale: result.rationale });
                }
            }

            if (scored.length === 0) continue;

            scored.sort((a, b) => b.score - a.score);
            const best = scored[0];
            usedFieldPaths.add(best.field.path);

            const mapping: FieldMapping = {
                canonicalKey: spec.key,
                sourceField: best.field,
                confidence: Number(Math.min(best.score, 1).toFixed(3)),
                matcherName: this.name,
                rationale: best.rationale.join('; '),
            };

            if (spec.multiLanguage) {
                const variants = this.collectLanguageVariants(spec, best.field, candidates, usedFieldPaths);
                if (Object.keys(variants).length > 0) {
                    mapping.languageVariants = variants;
                }
            }

            mappings.push(mapping);
        }

        return mappings;
    }

    private scoreField(
        spec: CanonicalFieldSpec,
        field: SchemaField,
        ctx: MatchContext,
    ): { score: number; rationale: string[] } {
        const rationale: string[] = [];
        let score = 0;

        const baseName = this.stripLanguageSuffix(field.name).baseName;
        const matchedIndex = spec.namePatterns.findIndex((p) => p.test(baseName));
        if (matchedIndex >= 0) {
            // Position-weighted: the first pattern is the most specific /
            // authoritative, so it gets the full bonus. Later patterns get
            // progressively less, ensuring `developer` beats `owner` and
            // `project_id` beats `id` when both fields exist on the same
            // schema.
            const positionWeight = 1 - (matchedIndex / Math.max(spec.namePatterns.length, 1)) * 0.4;
            const bonus = WEIGHTS.NAME_REGEX_HIT * positionWeight;
            score += bonus;
            rationale.push(
                `name "${field.name}" matches pattern[${matchedIndex}] ${spec.namePatterns[matchedIndex].source} (+${bonus.toFixed(3)})`,
            );
        }

        if (spec.descriptionPatterns && field.description) {
            const matched = spec.descriptionPatterns.find((p) => p.test(field.description!));
            if (matched) {
                score += WEIGHTS.DESCRIPTION_REGEX_HIT;
                rationale.push(`description matches ${matched.source} (+${WEIGHTS.DESCRIPTION_REGEX_HIT})`);
            }
        }

        if (this.typesAgree(spec.type, field)) {
            score += WEIGHTS.TYPE_AGREES;
            rationale.push(`type=${field.type ?? 'unknown'} agrees with canonical=${spec.type} (+${WEIGHTS.TYPE_AGREES})`);
        }

        if ((field as unknown as Record<string, unknown>).readonly) {
            score += WEIGHTS.READONLY_BONUS;
            rationale.push(`readOnly field bonus (+${WEIGHTS.READONLY_BONUS})`);
        }

        if (
            ctx.blockTags.some((t) => /(^|[_-])(new[_-]?)?proj(ect)?(s)?([_-]|$)/i.test(t))
        ) {
            score += WEIGHTS.BLOCK_TAG_PROJECT_BONUS;
            rationale.push(`block tag(s) signal project context (+${WEIGHTS.BLOCK_TAG_PROJECT_BONUS})`);
        }

        return { score, rationale };
    }

    private typesAgree(canonical: CanonicalFieldSpec['type'], field: SchemaField): boolean {
        const t = (field.type ?? '').toLowerCase();
        const fmt = (field.format ?? '').toLowerCase();
        switch (canonical) {
            case 'number':  return t === 'number' || t === 'integer';
            case 'boolean': return t === 'boolean';
            case 'date':    return t === 'string' && (fmt === 'date' || fmt === 'date-time' || fmt === 'datetime');
            case 'string':  return t === 'string' || t === '';
        }
    }

    /**
     * Determines whether a field name is a language variant of *another*
     * canonical field, so we don't mis-assign e.g. `name_es` to the
     * canonical `name` slot when the bare `name` field also exists.
     */
    private isLanguageVariantOf(_fieldName: string, _spec: CanonicalFieldSpec): boolean {
        // Currently a no-op: the actual variant collection below filters them.
        // Kept as a hook for future heuristics.
        return false;
    }

    private collectLanguageVariants(
        spec: CanonicalFieldSpec,
        canonicalField: SchemaField,
        allFields: SchemaField[],
        usedFieldPaths: Set<string>,
    ): Record<string, SchemaField> {
        const out: Record<string, SchemaField> = {};
        const baseName = this.stripLanguageSuffix(canonicalField.name).baseName;

        for (const f of allFields) {
            if (f.path === canonicalField.path) continue;
            if (usedFieldPaths.has(f.path)) continue;

            const stripped = this.stripLanguageSuffix(f.name);
            if (!stripped.langTag) continue;
            if (stripped.baseName.toLowerCase() !== baseName.toLowerCase()) continue;

            const matchesPattern = spec.namePatterns.some((p) => p.test(stripped.baseName));
            if (!matchesPattern) continue;

            out[stripped.langTag] = f;
            usedFieldPaths.add(f.path);
        }

        return out;
    }

    private stripLanguageSuffix(name: string): { baseName: string; langTag: string | null } {
        const m = name.match(LANGUAGE_TAG_RE);
        if (!m) return { baseName: name, langTag: null };

        const langCamel = m.groups?.langCamel;
        const lang = m.groups?.lang;
        const region = m.groups?.region;

        if (langCamel) {
            // CamelCase suffix like `descriptionEn` → strip last 2 chars
            return {
                baseName: name.slice(0, -2),
                langTag: langCamel.toLowerCase(),
            };
        }

        if (lang) {
            const tag = region ? `${lang}-${region}` : lang;
            return {
                baseName: name.slice(0, m.index!),
                langTag: tag,
            };
        }

        return { baseName: name, langTag: null };
    }
}

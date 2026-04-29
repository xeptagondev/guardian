/**
 * A field on the candidate (i.e. project) schema we're matching against.
 * Path is dot-notation reaching into `credentialSubject` so nested
 * objects ({ "location": { "country": "BR" } }) are addressable.
 */
export interface SchemaField {
    name: string;
    path: string;
    type?: string;            // JSON-Schema "type"
    format?: string;          // JSON-Schema "format" (date, date-time, uri…)
    description?: string;     // JSON-Schema "description"
    enum?: unknown[];
    refSchemaIri?: string;    // if "$ref" points to another schema
}

export type CanonicalFieldType = 'string' | 'number' | 'date' | 'boolean';

export interface CanonicalFieldSpec {
    /** Stable canonical key used as the column name in the project table. */
    key: string;
    /** Type-coerced output. */
    type: CanonicalFieldType;
    /** When true, sibling fields with language suffixes (description_en, description_es)
     *  are gathered into `extras.<key>_languages`. */
    multiLanguage?: boolean;
    /** Required for the project to be considered well-formed. */
    required?: boolean;
    /** Regex patterns matched against schema field names. */
    namePatterns: RegExp[];
    /** Optional patterns matched against the JSON-Schema `description`
     *  text — small bonus when they hit. */
    descriptionPatterns?: RegExp[];
}

export interface MatchContext {
    methodologyName: string | null;
    schemaName: string | null;
    schemaIri: string;
    role: string | null;
    /** Block tags that emit VCs of this schema (e.g. ["rvcdb_new_project"]). */
    blockTags: string[];
}

export interface FieldMapping {
    canonicalKey: string;
    sourceField: SchemaField;
    confidence: number;
    matcherName: string;
    rationale: string;
    /** Companion fields used for multi-language fan-out, indexed by language tag.
     *  Empty for non-multi-language fields. */
    languageVariants?: Record<string, SchemaField>;
}

export interface FieldMatcher {
    readonly name: string;
    match(
        canonical: CanonicalFieldSpec[],
        candidates: SchemaField[],
        ctx: MatchContext,
    ): Promise<FieldMapping[]>;
}

import { DecodedPolicy } from '../project-extraction/types';

export interface ProjectSchemaCandidate {
    /** Schema IRI as it appears in the policy block tree, e.g. "#79a25647…&1.0.0" */
    schemaIri: string;
    /** Parsed UUID portion of the IRI for joining with policy_schema rows. */
    schemaUuid: string;
    /** Parsed version portion of the IRI. */
    schemaVersion: string;
    /** Display name of the schema (from policy.schemas or policy_schema). */
    schemaName: string | null;
    /** Score in [0, 1]. >= 0.4 is treated as a usable project-schema candidate. */
    confidence: number;
    /** One-line human-readable explanation of how the score was reached. */
    rationale: string;
    /** Block tags that emit VCs of this schema (e.g. ["rvcdb_new_project"]). */
    sourceBlockTags: string[];
    /** Engine name that produced this candidate. */
    identifierName: string;
}

export interface IdentifyContext {
    /** Methodology display name from the policy (used by some engines as hints). */
    methodologyName: string | null;
}

/**
 * Identifies which schema(s) inside a decoded policy carry the
 * "primary project" data — i.e. the form a registrant fills in when
 * they register a new project.
 *
 * Different engines (regex, LLM, manual override) implement this same
 * interface and can be composed via an ensemble.
 */
export interface ProjectSchemaIdentifier {
    /** Engine name — surfaced in `extraction_meta` for debugging. */
    readonly name: string;

    /**
     * Returns candidates ranked by descending confidence. Caller picks
     * `result[0]` as the winner if `confidence >= threshold`.
     */
    identify(policy: DecodedPolicy, ctx: IdentifyContext): Promise<ProjectSchemaCandidate[]>;
}

/**
 * Types describing the inputs the project-extraction pipeline operates on.
 *
 * A `DecodedPolicy` is the shape produced by the policy-ingest worker — it
 * matches the columns of the `policy` table plus the `policy_schema` rows
 * for the same policy. Same shape that `decoded-policies-sample.json`
 * exports, so the CLI test script and the runtime pipeline share one type.
 */

export interface PolicyBlock {
    id?: string;
    tag?: string;
    blockType: string;
    permissions?: string[];
    children?: PolicyBlock[];
    schema?: string;             // schema IRI like "#<uuid>&<version>"
    presetSchema?: string;
    presetFields?: Array<Record<string, unknown>>;
    dependencies?: string[];
    [key: string]: unknown;
}

export interface PolicyClassifiedSchema {
    iri: string;
    uuid: string;
    version: string;
    name: string | null;
    description: string | null;
    entity: string | null;
    topicId: string | null;
    properties: string[];
    role: string;                // 'PROJECT_INFO' | 'SITE' | 'ISSUANCE' | 'MRV' | 'TOKENIZATION' | 'MONITORING' | 'REGISTRY' | 'LOCATION' | 'UNKNOWN'
}

export interface PolicySchemaFile {
    schemaId: string;
    schemaVersion: string;
    name: string | null;
    description: string | null;
    schemaFile: string;
    document: Record<string, unknown> | null;
}

export interface DecodedPolicy {
    instanceTopicId: string;
    policyTopicId: string;
    name: string | null;
    version: string | null;
    uuid: string | null;
    cid: string | null;
    messageTimestamp: string | null;
    config: PolicyBlock | null;                  // root block tree (policyJson.config)
    classifiedSchemas: PolicyClassifiedSchema[]; // policy.schemas
    tokens: Array<Record<string, unknown>>;
    schemaFiles: PolicySchemaFile[];             // joined from policy_schema
}

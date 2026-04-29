/**
 * Extracts the schema IRI a VC was minted against. Guardian VCs put it on
 * `credentialSubject.type` (sometimes plural / array). Returns the
 * normalized form `<uuid>&<version>` (no leading `#`) so it joins
 * cleanly with our `project_schema_resolution` rows.
 */
export interface ResolvedVcSchema {
    /** Normalized: `<uuid>&<version>` — primary form used throughout the system. */
    schemaIri: string;
    /** Same value with leading `#` — useful when emitting back to the policy block tree. */
    schemaIriHash: string;
    schemaUuid: string;
    schemaVersion: string;
}

export interface ParsedVc {
    /** The full VC document — what comes out of message.documents. */
    document: Record<string, unknown>;
    /** First credentialSubject we recognised. Always an object. */
    credentialSubject: Record<string, unknown>;
}

const IRI_PATTERN = /^#?([0-9a-fA-F-]{36})&(.+)$/;

export function resolveVcSchema(document: Record<string, unknown> | null | undefined): {
    parsed: ParsedVc;
    schema: ResolvedVcSchema | null;
} | null {
    if (!document || typeof document !== 'object') return null;

    const csRaw = (document as Record<string, unknown>).credentialSubject;
    if (!csRaw) return null;

    // credentialSubject can be an object or an array of objects.
    const cs = Array.isArray(csRaw)
        ? csRaw.find((x) => x && typeof x === 'object' && !Array.isArray(x)) as Record<string, unknown> | undefined
        : (csRaw as Record<string, unknown>);
    if (!cs || typeof cs !== 'object') return null;

    const parsed: ParsedVc = { document, credentialSubject: cs };

    // type can be `"#abc&1.0.0"`, `["#abc&1.0.0"]`, or
    // `["VerifiableCredentialSubject", "#abc&1.0.0"]`.
    const typeRaw = cs['type'] ?? cs['@type'];
    const types = Array.isArray(typeRaw) ? typeRaw : typeRaw ? [typeRaw] : [];

    for (const t of types) {
        if (typeof t !== 'string') continue;
        const m = t.match(IRI_PATTERN);
        if (!m) continue;
        return {
            parsed,
            schema: {
                schemaIriHash: t.startsWith('#') ? t : `#${t}`,
                schemaIri: t.replace(/^#/, ''),
                schemaUuid: m[1],
                schemaVersion: m[2],
            },
        };
    }

    return { parsed, schema: null };
}

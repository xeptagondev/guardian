import { SchemaField } from '../matchers/field-matcher.interface';

/**
 * Resolves a JSON-Schema `$ref` IRI (e.g. "#afd4c319-…&1.0.0") to the
 * referenced schema's `document`. Supplied by the caller so the flattener
 * stays decoupled from the storage layer.
 */
export type SchemaRefResolver = (refIri: string) => Record<string, unknown> | null | undefined;

/**
 * Walks a JSON-Schema `properties` object and emits a flat list of
 * SchemaField entries the FieldMatcher can score.
 *
 * Supports:
 *   - top-level scalar fields (the common case)
 *   - one level of nested object: `location: { country, region }`
 *     → exposed as `location.country`, `location.region`
 *   - one level of array-of-object: `locations: [{ country, region }]`
 *     → exposed as `locations.0.country`, `locations.0.region`
 *   - `$ref` resolution into other schemas in the same policy package
 *     (typical for Guardian, where complex sub-types like Location and
 *     Coordinates are pulled out into separate schema files).
 *
 * Guardian schemas usually carry their @-prefixed JSON-LD plumbing
 * (`@context`, `@id`, etc.) as properties — those are filtered out.
 */
export function flattenSchemaProperties(
    document: Record<string, unknown> | null | undefined,
    pathPrefix = '',
    depth = 0,
    refResolver?: SchemaRefResolver,
    visitedRefs: Set<string> = new Set(),
): SchemaField[] {
    if (!document || typeof document !== 'object') return [];

    const props = (document as Record<string, unknown>).properties;
    if (!props || typeof props !== 'object' || Array.isArray(props)) return [];

    const out: SchemaField[] = [];
    for (const [name, raw] of Object.entries(props as Record<string, unknown>)) {
        if (name.startsWith('@')) continue;
        if (!raw || typeof raw !== 'object') continue;

        const desc = raw as Record<string, unknown>;
        const path = pathPrefix ? `${pathPrefix}.${name}` : name;

        const field: SchemaField = {
            name,
            path,
            type: typeof desc.type === 'string' ? desc.type : undefined,
            format: typeof desc.format === 'string' ? desc.format : undefined,
            description: typeof desc.description === 'string' ? desc.description : undefined,
            enum: Array.isArray(desc.enum) ? desc.enum : undefined,
            refSchemaIri: typeof desc.$ref === 'string' ? desc.$ref : undefined,
        };
        out.push(field);

        // Cap recursion at depth 2 — deeper structures are rare and would just
        // add noise. (Top-level → object/array sub-schema → leaf scalars.)
        if (depth >= 2) continue;

        // Resolve `$ref` into another policy schema (e.g. Locations sub-schema).
        if (typeof desc.$ref === 'string' && refResolver) {
            const refDoc = visitRef(desc.$ref, refResolver, visitedRefs);
            if (refDoc) {
                out.push(...flattenSchemaProperties(refDoc, path, depth + 1, refResolver, visitedRefs));
            }
            continue;
        }

        // Nested object: { type: 'object', properties: {...} }
        if (desc.type === 'object') {
            out.push(...flattenSchemaProperties(desc, path, depth + 1, refResolver, visitedRefs));
            continue;
        }

        // Array of objects (or array of $ref): take the first element's shape.
        if (desc.type === 'array' && desc.items && typeof desc.items === 'object' && !Array.isArray(desc.items)) {
            const items = desc.items as Record<string, unknown>;
            const itemsPath = `${path}.0`;
            if (typeof items.$ref === 'string' && refResolver) {
                const refDoc = visitRef(items.$ref, refResolver, visitedRefs);
                if (refDoc) {
                    out.push(...flattenSchemaProperties(refDoc, itemsPath, depth + 1, refResolver, visitedRefs));
                }
            } else if (items.type === 'object') {
                out.push(...flattenSchemaProperties(items, itemsPath, depth + 1, refResolver, visitedRefs));
            }
        }
    }

    return out;
}

/** Loads a referenced schema while preventing $ref cycles. */
function visitRef(
    refIri: string,
    resolver: SchemaRefResolver,
    visited: Set<string>,
): Record<string, unknown> | null {
    const normalized = refIri.replace(/^#/, '').toLowerCase();
    if (visited.has(normalized)) return null;
    visited.add(normalized);
    const doc = resolver(refIri);
    return doc ?? null;
}

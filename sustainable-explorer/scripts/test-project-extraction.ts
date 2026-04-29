/* eslint-disable no-console */
/**
 * Smoke-test the full project-extraction pipeline (identifier + matcher)
 * against the sample export at sample_data/decoded-policies-sample.json.
 *
 * Run from sustainable-explorer/:
 *
 *   yarn test:project-extraction
 *
 * No DB required.
 */

import { promises as fs } from 'fs';
import path from 'path';
import {
    DecodedPolicy,
} from '../src/worker/services/project-extraction/types';
import { RegexProjectSchemaIdentifier } from '../src/worker/services/matchers/regex-project-schema-identifier';
import { RegexFieldMatcher } from '../src/worker/services/matchers/regex-field-matcher';
import { CANONICAL_PROJECT_FIELDS } from '../src/worker/services/project-extraction/canonical-fields';
import { flattenSchemaProperties } from '../src/worker/services/project-extraction/schema-field-flattener';

const SAMPLE_PATH = path.join(__dirname, '..', 'sample_data', 'decoded-policies-sample.json');

async function main(): Promise<void> {
    const raw = await fs.readFile(SAMPLE_PATH, 'utf-8');
    const policies = JSON.parse(raw) as DecodedPolicy[];

    const identifier = new RegexProjectSchemaIdentifier();
    const matcher = new RegexFieldMatcher();

    console.log(`\nLoaded ${policies.length} policies\n`);
    console.log('═'.repeat(96));

    for (const policy of policies) {
        console.log(`\n📘 ${policy.name ?? '<unnamed>'}`);
        console.log(`   instanceTopic=${policy.instanceTopicId}  policyTopic=${policy.policyTopicId}`);

        const candidates = await identifier.identify(policy, { methodologyName: policy.name });
        const winners = candidates.filter(
            (c) => c.confidence >= RegexProjectSchemaIdentifier.THRESHOLD,
        );

        if (winners.length === 0) {
            console.log('   ❌ no project schema identified');
            continue;
        }

        for (const winner of winners) {
            console.log(`\n   🏆 Project schema: ${winner.schemaName}`);
            console.log(`      iri=${winner.schemaIri}  conf=${winner.confidence.toFixed(3)}  blockTags=${winner.sourceBlockTags.join(', ')}`);

            const file = policy.schemaFiles.find((f) => f.schemaId === winner.schemaUuid);
            if (!file?.document) {
                console.log('      ⚠️  no schema document — cannot run field matcher');
                continue;
            }

            const refResolver = (refIri: string): Record<string, unknown> | null => {
                const cleaned = refIri.replace(/^#/, '');
                const [uuid, version] = cleaned.split('&');
                const found = policy.schemaFiles.find(
                    (f) => f.schemaId.toLowerCase() === uuid.toLowerCase() && f.schemaVersion === version,
                );
                return found?.document ?? null;
            };
            const fields = flattenSchemaProperties(file.document, '', 0, refResolver);
            const role = policy.classifiedSchemas.find(
                (s) => s.iri.replace(/^#/, '').toLowerCase() === winner.schemaIri.replace(/^#/, '').toLowerCase(),
            )?.role ?? null;

            const mappings = await matcher.match(CANONICAL_PROJECT_FIELDS, fields, {
                methodologyName: policy.name,
                schemaName: winner.schemaName,
                schemaIri: winner.schemaIri,
                role,
                blockTags: winner.sourceBlockTags,
            });

            console.log(`\n      Field mapping (${mappings.length}/${CANONICAL_PROJECT_FIELDS.length} canonical fields covered):`);
            const found = new Set<string>();
            for (const m of mappings) {
                found.add(m.canonicalKey);
                const langs = m.languageVariants ? `  langs=[${Object.keys(m.languageVariants).join(',')}]` : '';
                console.log(`        ✓ ${m.canonicalKey.padEnd(15)} → ${m.sourceField.path.padEnd(28)} (conf=${m.confidence.toFixed(2)})${langs}`);
            }
            const missing = CANONICAL_PROJECT_FIELDS
                .filter((f) => !found.has(f.key))
                .map((f) => f.key);
            if (missing.length > 0) {
                console.log(`        ✗ missing: ${missing.join(', ')}`);
            }
        }
    }

    console.log('\n' + '═'.repeat(96) + '\nDone.\n');
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});

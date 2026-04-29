/* eslint-disable no-console */
/**
 * Smoke-test the RegexProjectSchemaIdentifier against the JSON export
 * at sample_data/decoded-policies-sample.json.
 *
 * Run from sustainable-explorer/:
 *
 *   yarn test:project-identifier
 *
 * No DB required.
 */

import { promises as fs } from 'fs';
import path from 'path';
import { RegexProjectSchemaIdentifier } from '../src/worker/services/matchers/regex-project-schema-identifier';
import { DecodedPolicy } from '../src/worker/services/project-extraction/types';

const SAMPLE_PATH = path.join(__dirname, '..', 'sample_data', 'decoded-policies-sample.json');

async function main(): Promise<void> {
    const raw = await fs.readFile(SAMPLE_PATH, 'utf-8');
    const policies = JSON.parse(raw) as DecodedPolicy[];
    const identifier = new RegexProjectSchemaIdentifier();

    console.log(`\nLoaded ${policies.length} policies from ${path.basename(SAMPLE_PATH)}\n`);
    console.log(`Identifier: ${identifier.name} (threshold: ${RegexProjectSchemaIdentifier.THRESHOLD})\n`);
    console.log('─'.repeat(96));

    for (const policy of policies) {
        const candidates = await identifier.identify(policy, {
            methodologyName: policy.name,
        });

        const winner = candidates.find((c) => c.confidence >= RegexProjectSchemaIdentifier.THRESHOLD) ?? null;

        console.log(`\n📘 ${policy.name ?? '<unnamed policy>'}`);
        console.log(`   instanceTopicId: ${policy.instanceTopicId}`);
        console.log(`   policyTopicId:   ${policy.policyTopicId}`);
        console.log(`   schemaCount:     ${policy.schemaFiles.length}`);

        if (candidates.length === 0) {
            console.log('   ❌ no VC-producing blocks found in policy.config');
            continue;
        }

        console.log(`\n   Candidates (top ${Math.min(5, candidates.length)} of ${candidates.length}):`);
        for (const [i, c] of candidates.slice(0, 5).entries()) {
            const marker = c === winner ? '🏆' : '  ';
            const tags = c.sourceBlockTags.length
                ? c.sourceBlockTags.slice(0, 3).join(', ') + (c.sourceBlockTags.length > 3 ? ', …' : '')
                : '<none>';
            console.log(
                `   ${marker} [${i + 1}] ${c.confidence.toFixed(3)}  ${c.schemaName ?? '<unnamed>'}`,
            );
            console.log(`         iri:    ${c.schemaIri}`);
            console.log(`         tags:   ${tags}`);
            console.log(`         why:    ${c.rationale}`);
        }

        if (!winner) {
            console.log(`\n   ⚠️  no candidate cleared threshold ${RegexProjectSchemaIdentifier.THRESHOLD}`);
        }
    }

    console.log('\n' + '─'.repeat(96));
    console.log('Done.\n');
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});

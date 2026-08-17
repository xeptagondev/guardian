# Amana Solar Rooftop: why `instanceTopicId` was never captured

Deep-dive into why `business_view.relatedTopicId` was NULL for methodology
"Amana Solar Rooftop" (`business_view.id = 375483`), tracing the gap from raw
Hedera mirror-node ingestion through parsing, decode, and downstream
consumers. The reachability fix (frontend/backend fallback so the row is
clickable) is already applied and out of scope here — this is the pipeline
root-cause analysis.

## Summary

**Root cause: (b) — a genuine historical Guardian payload gap, but one whose
data is fully recoverable and simply never looked up.** The 2022-era
`Instance-Policy`/`publish-policy` message for this policy shipped
`"instanceTopicId": null` — Guardian at that time didn't inline the child
instance-topic id into the publish-policy payload. It announced the instance
topic 21 seconds later via a **separate** `Topic`/`create-topic` message
carrying `options.messageType = 'INSTANCE_POLICY_TOPIC'` and
`options.childId = '0.0.1381030'`. That sibling message is parsed correctly
and sits in the `message` table today. Nothing downstream reads it as a
fallback: `business-view-builder.processor.ts`, `topic-classifier.ts`, and
the `policy.instanceTopicId` write path all key exclusively off
`Instance-Policy.options.instanceTopicId`.

**Blast radius: exactly 1 policy topic** out of 123 `publish-policy`
messages in the DB (query below), and independently confirmed fixable via
the sibling-message pattern. However, the same gap that nulls
`business_view.relatedTopicId` for the methodology row **also** propagates
into `policy.instanceTopicId` and from there into all 5 `PROJECT` rows under
this policy (`businessData.instanceTopicId` is empty on every one) — so the
practical impact is wider than "one unreachable detail page": methodology↔
project joins used for supply-chain counts, issuance totals, and the
methodology-stats materialized view are all silently broken for this one
methodology.

## Topic sync pipeline, step by step

### 1. Raw ingestion is correct — the gap is in the source payload

All 19 raw messages on topic `0.0.1380970` (Amana's policy topic), in order
(`docker exec se-postgres psql ... "SELECT ... FROM message WHERE
\"topicId\" = '0.0.1380970' ORDER BY \"consensusTimestamp\""`):

| id | consensusTimestamp | type | action | relevant options |
|---|---|---|---|---|
| 1287 | 1666704580 | Topic | create-topic | `messageType: POLICY_TOPIC` |
| 1288–1303 | … | Schema | publish-*/create-schema | schema publishes |
| **1304** | **1666705883.609541003** | **Instance-Policy** | **publish-policy** | `topicId: 0.0.1380970`, **`instanceTopicId: null`** (literal `null`, not absent), `policyTopicId: 0.0.1380970` |
| **1305** | **1666705904.774270747** | **Topic** | **create-topic** | `messageType: INSTANCE_POLICY_TOPIC`, `childId: 0.0.1381030`, `parentId: null` |

Message 1304 is the row `business-view-builder.processor.ts` reads. Its
`options.instanceTopicId` key is present in the JSON but its value is
`null` — confirming the raw Hedera payload itself never carried a value
here, not a parsing failure. `src/shared/utils/message-parser.ts:113`
(`extractFields`, case `'Instance-Policy'`) does
`instanceTopicId: json['instanceTopicId'] || null` — running this exact
2022 payload through current parsing logic today would produce the same
`null`. **This part is genuinely un-fixable by improving the parser**: the
field is absent from the source.

Message 1305 — posted 21 seconds later, same topic — is the actual
announcement of the child instance topic, using the `INSTANCE_POLICY_TOPIC`
message-type convention. `message-parser.ts:85-94` (case `'Topic'`) parses
this correctly: `childId: json['childId'] || json['topicId'] || null`, so
`message.options.childId = '0.0.1381030'` is sitting in the DB, correctly
parsed, right now.

### 2. `0.0.1381030` is confirmed to be the real, live instance topic

Querying `message WHERE "topicId" = '0.0.1381030'` returns 6 rows — this is
not an orphaned/dead topic id, it's an active instance topic with its own
message feed:

```
seq 1: Topic/create-topic  messageType=INSTANCE_POLICY_TOPIC parentId=0.0.1380970 childId=null
seq 2: Topic/create-topic  "Ex Ante Data Template"        messageType=DYNAMIC_TOPIC childId=0.0.1381067
seq 3: Topic/create-topic  "Project"                      messageType=DYNAMIC_TOPIC childId=0.0.1381069
seq 4: Topic/create-topic  "Data Template"                messageType=DYNAMIC_TOPIC childId=0.0.1381111
seq 5: Topic/create-topic  "Emission Reduction Template"  messageType=DYNAMIC_TOPIC childId=0.0.1381119
seq 6: Topic/create-topic  "Issuance Certificate"         messageType=DYNAMIC_TOPIC childId=0.0.1381134
```

Message seq 1 (posted *on* `0.0.1381030` itself) declares
`options.parentId = '0.0.1380970'` — the reverse link back to the policy
topic — plus the same `messageType: INSTANCE_POLICY_TOPIC` tag. The other 5
are the instance's standard sub-topics (Project, mint templates, issuance
certificates) — exactly the shape a normal, healthy instance topic has. This
independently corroborates that `0.0.1381030` is the real instance topic,
not a red herring.

### 3. VC ingestion and project-mapping already work around the gap — via a different mechanism

`src/worker/processors/message-process.processor.ts:356-398`
(`resolveParentPolicyTopicId`, used by `enqueueVcIpfsFetchIfReady` to decide
when a VC's parent policy is decoded) walks the topic tree **upward** via
`Topic.options.parentId`, not via `Instance-Policy.options.instanceTopicId`
first:

```ts
// Check if this topic is itself an Instance-Policy topic
... WHERE type = 'Instance-Policy' AND action = 'publish-policy' AND "topicId" = $1
// Also check instanceTopicId — policies reference their instance topic
... WHERE type = 'Instance-Policy' AND action = 'publish-policy' AND options->>'instanceTopicId' = $1
// Walk one level up via Topic parentId
... WHERE type = 'Topic' AND "topicId" = $1   -- SELECT options->>'parentId'
```

Starting from a VC under `0.0.1381030`'s subtree (e.g. topic `0.0.1381069`,
"Project"), the walk reaches `0.0.1381030`, and the `parentId` lookup there
reads message seq 1's `options.parentId = '0.0.1380970'` — landing on
`0.0.1380970`, which *is* a real `Instance-Policy`/`publish-policy` topic.
The walk succeeds **without ever needing `options.instanceTopicId`**,
because it uses the reverse pointer (`parentId` on the child) rather than
the forward pointer (`instanceTopicId` on the parent).

This is confirmed empirically: `policy_decode_status` shows this policy's
decode as `status='success'`, and `business_view` has 5 real `PROJECT` rows
whose `businessData->>'policyTopicId' = '0.0.1380970'` (ids 375836–375840,
one of them literally titled "Amana Solar Rooftop"). VC ingestion, IPFS
fetch gating, and project mapping all worked correctly for this policy
despite the missing field — they just don't use it.

### 4. Two consumers *do* key exclusively off `Instance-Policy.options.instanceTopicId`, and both are broken here

**`business-view-builder.processor.ts:79-83`** (already known):

```sql
CASE
    WHEN m.type = 'Instance-Policy' THEN m.options->>'instanceTopicId'
    WHEN m.type = 'Token'           THEN m."topicId"
    ELSE m.options->>'topicId'
END,
```

No fallback to the sibling `Topic`/`INSTANCE_POLICY_TOPIC` message. Result:
`relatedTopicId = NULL` for this one `business_view` METHODOLOGY row.

**`src/worker/project-mapper/topic-classifier.ts:65-73`** (`isInstanceTopic`):

```ts
const rows = await dataSource.query(
    `SELECT 1 FROM message
     WHERE type = 'Instance-Policy' AND options->>'instanceTopicId' = $1
     LIMIT 1`,
    [topicId],
);
```

Same single-field dependency. Calling `classifyTopic(ds, '0.0.1381030')`
today returns `kind: 'other', instancePolicyTopicId: null` — it would
misclassify the real instance topic. `test/unit/worker/project-mapper/
topic-classifier.spec.ts` only exercises the `instanceTopicId`-present path
(its mock literally keys off `sql.includes('instanceTopicId')`) — there is
no test, and no code path, for the `INSTANCE_POLICY_TOPIC` sibling-message
pattern anywhere in `TopicClassifierService`.

**Downstream of both:** `policy.instanceTopicId` (populated in
`policy-decode.processor.ts:91-119`, threaded from
`message-process.processor.ts:184-197`'s `optionInstanceTopicId =
parsed.options['instanceTopicId']`, and re-threaded on every boot-time
rescue by `sync-scheduler.service.ts:416-458`
`schedulePolicyDecodeJobs`/`instance_topic_id: COALESCE(m.options->>
'instanceTopicId', '')`) is *also* null for this policy, because every one
of those call sites reads the same single field. `ProjectMapperService`
(`src/worker/services/project-mapper.service.ts:139`) then copies
`policyRow.instanceTopicId` straight into each PROJECT row's
`businessData.instanceTopicId` — confirmed empty on all 5 Amana project
rows:

```
 id     | viewType | displayName          | businessData.instanceTopicId | businessData.policyTopicId
 375836 | PROJECT  | cbd76908-...         | (empty)                      | 0.0.1380970
 375837 | PROJECT  | Amana Solar Rooftop  | (empty)                      | 0.0.1380970
 375838 | PROJECT  | e11a7414-...         | (empty)                      | 0.0.1380970
 375839 | PROJECT  | d8f29333-...         | (empty)                      | 0.0.1380970
 375840 | PROJECT  | e3c33e9c-...         | (empty)                      | 0.0.1380970
```

This means the methodology↔project join used throughout the API layer
(`bv_meth."relatedTopicId" = bv."businessData"->>'instanceTopicId'` —
`src/api/repositories/pg-project.repository.ts:119-123`,
`pg-methodology.repository.ts:501-537`, `pg-issuance.repository.ts:76`, and
the `mv_methodology_stats` materialized view definitions,
`src/shared/materialized-views/methodology-stats.mv.ts:50-125`) can never
match for Amana — it's a doubly-broken join, since `relatedTopicId` is NULL
*and* `businessData.instanceTopicId` is empty on the other side. Practical
effect: Amana's project count / issuance totals / supply-chain rollups on
the methodology's own stats are silently wrong (undercounted), independent
of and in addition to the already-fixed detail-page unreachability.

## IPFS / policy artifact findings

`policy_decode_status` (this DB's live table — see caveat below) shows:

```
policyTopicId | sourceCid                                                    | status
0.0.1380970   | bafkreiemd2g2lyai4ao6f2wdo73zmiu43bmua6vbaugkzxhqvtzlbqqcge   | success
```

**Caveat on schema drift:** the currently-loaded Postgres dump
(`se-postgres`) does **not** have the `policy` table that current code
(`src/shared/entities/policy.entity.ts`, `policy-decode.processor.ts`,
`mapping-reprocess.service.ts`, etc.) reads and writes — `\dt` shows only
`policy_decode_status` and `policy_schema`, an older/different table shape
(columns like `categoriesExport`, `sectoralScopes`, `schemaLabelMap` that
don't exist on the `Policy` entity at all). This dump predates the current
`policy` table schema. So I could not query the live `rawPolicyJson` /
`instanceTopicId` column for this record directly — that check is
unavailable in this environment, not a "not present" finding. Flagging
explicitly rather than guessing.

**Local ZIP cache**: `data/policy-zips/` (rooted per
`LocalPolicyZipStorage`, `src/worker/services/storage/
local-policy-zip-storage.service.ts:12`, `POLICY_ZIP_STORAGE_PATH` env,
default `./data/policy-zips`) contains ~120 cached `.zip` files, all with
`bafybei…` CIDs (CIDv1 dag-pb, i.e. actual zip/folder content). The Amana
CID `bafkreiemd2g2lyai4ao6f2wdo73zmiu43bmua6vbaugkzxhqvtzlbqqcge` uses the
`bafkrei…` prefix (CIDv1 **raw** codec — a single leaf blob, not a
UnixFS folder) and is **not present** in the cache directory or in the
`ipfs_files` DB cache table (`SELECT ... FROM ipfs_files WHERE cid =
'bafkrei...'` → 0 rows). Consistent with this being a much older-shape
Guardian artifact (2022) that may not even have been a zip at the protocol
level, and it was never re-fetched under current code. **Could not inspect
the decoded policy.json content for an inline instance-topic reference** —
no cached artifact exists to grep. This is a gap in what's checkable, not
evidence the id is/isn't embedded there.

## Root cause

**(b) — recoverable extraction/join gap**, with a genuine (a)-flavored
origin:

- The *origin* is a real historical Guardian payload limitation: the 2022
  `publish-policy` message never carried `instanceTopicId` inline. Current
  parsing logic is not buggy here — `message-parser.ts:113` correctly
  reflects what's in the source JSON (`null`), and re-running it today on
  this exact payload changes nothing.
- But the *data is not actually missing from the system* — it arrived 21
  seconds later as a distinct, correctly-parsed message
  (`messageType: INSTANCE_POLICY_TOPIC`, `options.childId`), and is sitting
  in `message` right now. The gap is that three consumers
  (`business-view-builder.processor.ts`, `topic-classifier.ts`, and the
  `policy.instanceTopicId` write path) only ever look at one field on one
  message type, with no fallback to this well-known sibling-message
  convention — even though a fourth consumer
  (`resolveParentPolicyTopicId` in `message-process.processor.ts`) already
  demonstrates a working, field-independent way to resolve the same
  relationship (walking `Topic.options.parentId` instead of trusting
  `instanceTopicId`).

None of the four existing docs reviewed cover this exact gap:
- `docs/reparse-multi-version-instance-topic-issue.md` — a *different*
  instance-topic issue (VC `policyId` vs. on-chain topic-parent disagreeing
  about *which version* of a multi-republished policy a project belongs
  to). Confirms `instanceTopicId` is normally populated via
  `queryPolicyByPolicyId` → `policy.instanceTopicId`, consistent with what's
  found here, but doesn't address the null-source case.
- `docs/methodology-mapping-bugs-investigation.md` — field-mapping/
  reparse bugs (title resolution, `isProjectSchema` overload, project-
  schema classification self-heal). Unrelated to instance-topic resolution.
- `docs/field-mapping-and-reparse-flow.md` — describes the mapping-edit →
  reparse flow generally; doesn't touch instance-topic discovery.
- `docs/architecture/decode-flow.md` — documents the *expected/normal*
  shape (`options.instanceTopicId = 0.0.3300440` inline on the
  publish-policy message, §2) as the only mechanism, with no mention of the
  `INSTANCE_POLICY_TOPIC` sibling-message fallback pattern seen here. This
  doc would benefit from a short addendum once/if this gap is fixed.

## Blast radius

```sql
-- messages with the gap
SELECT count(*) FROM message m
WHERE m.type = 'Instance-Policy' AND m.action = 'publish-policy'
  AND (m.options->>'instanceTopicId' IS NULL OR m.options->>'instanceTopicId' = '');
-- => 1

-- of those, how many are recoverable via the sibling INSTANCE_POLICY_TOPIC message
SELECT count(*) FROM message m
WHERE m.type = 'Instance-Policy' AND m.action = 'publish-policy'
  AND (m.options->>'instanceTopicId' IS NULL OR m.options->>'instanceTopicId' = '')
  AND EXISTS (
    SELECT 1 FROM message s
    WHERE s."topicId" = m."topicId" AND s.type = 'Topic' AND s.action = 'create-topic'
      AND s.options->>'messageType' = 'INSTANCE_POLICY_TOPIC'
      AND s.options->>'childId' IS NOT NULL AND s.options->>'childId' <> ''
  );
-- => 1

-- total publish-policy messages in the DB, for context
-- => 123

-- business_view confirmation
SELECT count(*) FROM business_view WHERE "viewType"='METHODOLOGY' AND "relatedTopicId" IS NULL;
-- => 1
```

**Isolated legacy case: 1 of 123 publish-policy messages, and the fallback
fix would resolve exactly that 1.** This is not a broad systemic pattern in
the current dataset — it's specific to this one 2022-era policy (and
plausibly to whichever narrow window of old Guardian versions used the
two-message `INSTANCE_POLICY_TOPIC` convention instead of inlining
`instanceTopicId`). Worth re-running this same query after every future
mirror-node backfill/re-sync, since older policies not yet crawled could
reintroduce the same shape.

## Recommendation

The already-applied frontend/backend fix (reachability by DB id) is
sufficient for "can an admin open this page." It does **not** fix the
methodology↔project join gap described in §4 above. Two independent
follow-ups, in order of leverage:

**1. `business-view-builder.processor.ts:79-83`** — add a lateral fallback
so `relatedTopicId` recovers from the sibling `INSTANCE_POLICY_TOPIC`
message when `options.instanceTopicId` is empty:

```sql
CASE
    WHEN m.type = 'Instance-Policy' THEN COALESCE(
        NULLIF(m.options->>'instanceTopicId', ''),
        inst_topic."childId"
    )
    WHEN m.type = 'Token' THEN m."topicId"
    ELSE m.options->>'topicId'
END,
```
joined via:
```sql
LEFT JOIN LATERAL (
    SELECT s.options->>'childId' AS "childId"
    FROM message s
    WHERE m.type = 'Instance-Policy'
      AND s."topicId" = m."topicId"
      AND s.type = 'Topic'
      AND s.action = 'create-topic'
      AND s.options->>'messageType' = 'INSTANCE_POLICY_TOPIC'
    ORDER BY s."consensusTimestamp" ASC
    LIMIT 1
) inst_topic ON true
```
This alone fixes the METHODOLOGY row's `relatedTopicId` (the originally
reported symptom) for this and any future record of the same shape — cheap,
one extra indexed lookup per `Instance-Policy` row (`IDX_ba61dccaec…` on
`topicId` already covers it).

**2. Propagate the same fallback to `policy.instanceTopicId`** so the
PROJECT-side of the join also heals — this is the piece that fixes the
wider stats/rollup breakage, not just the detail page:
- `message-process.processor.ts:184-187` — when computing
  `optionInstanceTopicId` for the `POLICY_DECODE` job payload, apply the
  same sibling-message lookup before falling back to `null`.
- `sync-scheduler.service.ts:416-458` (`schedulePolicyDecodeJobs`) and
  `:467-486` (`rescheduleOrphanedTopics`) — same fallback in their
  `instance_topic_id` / `refs.topic_id` derivations, since both currently
  read `m.options->>'instanceTopicId'` only.
- `topic-classifier.ts:65-73` (`isInstanceTopic`) — same fallback, so
  `TopicClassifierService` correctly recognizes `0.0.1381030` as an
  instance topic if/when it's ever consulted for this subtree.

Given the blast radius is 1 record, a targeted, low-risk backfill (a
one-off `UPDATE policy SET "instanceTopicId" = '0.0.1381030' WHERE
"policyTopicId" = '0.0.1380970'` plus a `business_view` project-row
reparse) is likely more proportionate than generalizing all four call sites
immediately — but the SQL fallback pattern above is identical across all of
them, so if a second legacy record with this shape surfaces later, the same
lateral-join fix can be copy-pasted into each.

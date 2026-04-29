import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    Index,
    Unique,
    CreateDateColumn,
    UpdateDateColumn,
} from 'typeorm';

/**
 * One row per "project" — extracted from a VC produced by a Guardian policy
 * block tagged as the project source (see RegexProjectSchemaIdentifier).
 *
 * `consensusTimestamp` is the unique key: every VC on Hedera has one and it
 * never changes, so re-extraction is idempotent.
 *
 * `rawVc` keeps the source VC verbatim. `extras` holds anything the
 * field matcher couldn't map into a canonical column, including
 * language variants of multi-language fields (e.g. `description_es`).
 * `extractionMeta` records which engines + confidences produced this row
 * for debuggability.
 */
@Entity('project')
@Unique(['consensusTimestamp'])
export class Project {
    @PrimaryGeneratedColumn({ type: 'bigint' })
    id: string;

    @Index()
    @Column({ type: 'varchar', length: 40 })
    consensusTimestamp: string;

    @Index()
    @Column({ type: 'varchar', length: 30 })
    dynamicTopicId: string;

    @Index()
    @Column({ type: 'varchar', length: 30 })
    methodologyTopicId: string;

    @Index()
    @Column({ type: 'varchar', length: 30 })
    instanceTopicId: string;

    @Column({ type: 'varchar', length: 255 })
    schemaIri: string;

    // ── Canonical UI fields (subset chosen for filters/listing/cards) ────
    @Index()
    @Column({ type: 'varchar', length: 255, nullable: true })
    projectId: string | null;

    @Column({ type: 'text', nullable: true })
    name: string | null;

    @Column({ type: 'text', nullable: true })
    description: string | null;

    @Index()
    @Column({ type: 'varchar', length: 80, nullable: true })
    country: string | null;

    @Column({ type: 'varchar', length: 8, nullable: true })
    countryCode: string | null;

    @Column({ type: 'varchar', length: 120, nullable: true })
    region: string | null;

    @Column({ type: 'numeric', precision: 9, scale: 6, nullable: true })
    latitude: string | null;

    @Column({ type: 'numeric', precision: 9, scale: 6, nullable: true })
    longitude: string | null;

    @Column({ type: 'date', nullable: true })
    startDate: string | null;

    @Column({ type: 'date', nullable: true })
    endDate: string | null;

    @Column({ type: 'varchar', length: 40, nullable: true })
    vintage: string | null;

    @Column({ type: 'text', nullable: true })
    proponentName: string | null;

    @Index()
    @Column({ type: 'varchar', length: 40, nullable: true })
    status: string | null;

    @Index()
    @Column({ type: 'varchar', length: 120, nullable: true })
    methodologyTag: string | null;

    @Index()
    @Column({ type: 'varchar', length: 80, nullable: true })
    sector: string | null;

    @Column({ type: 'varchar', length: 80, nullable: true })
    category: string | null;

    @Index()
    @Column({ type: 'varchar', length: 80, nullable: true })
    projectType: string | null;

    // ── Lossless data ────────────────────────────────────────────────────
    @Column({ type: 'jsonb' })
    rawVc: Record<string, unknown>;

    @Column({ type: 'jsonb' })
    extras: Record<string, unknown>;

    @Column({ type: 'jsonb' })
    extractionMeta: Record<string, unknown>;

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;
}

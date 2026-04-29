import {
    Entity,
    PrimaryColumn,
    Column,
    Index,
    CreateDateColumn,
    UpdateDateColumn,
} from 'typeorm';

/**
 * Per (policyTopicId, schemaUuid, schemaVersion), records:
 *   - whether this schema represents a project (decision by some
 *     ProjectSchemaIdentifier engine), and
 *   - the field mapping produced by some FieldMatcher engine.
 *
 * Caches both decisions so the per-VC ProjectExtractor stays cheap;
 * recomputed only when matcher_version bumps or an admin clears the row.
 */
@Entity('project_schema_resolution')
@Index('project_schema_resolution_iri_idx', ['policyTopicId', 'schemaIri'])
export class ProjectSchemaResolution {
    @PrimaryColumn({ type: 'varchar', length: 30 })
    policyTopicId: string;

    @PrimaryColumn({ type: 'varchar', length: 60 })
    schemaUuid: string;

    @PrimaryColumn({ type: 'varchar', length: 50 })
    schemaVersion: string;

    @Column({ type: 'varchar', length: 255 })
    schemaIri: string;

    @Column({ type: 'varchar', length: 255, nullable: true })
    schemaName: string | null;

    @Column({ type: 'boolean', default: false })
    isProjectSchema: boolean;

    @Column({ type: 'varchar', length: 60 })
    identifierName: string;

    @Column({ type: 'numeric', precision: 4, scale: 3, nullable: true })
    identifierConfidence: string | null;

    @Column({ type: 'jsonb' })
    candidates: Array<Record<string, unknown>>;

    @Column({ type: 'jsonb', nullable: true })
    fieldMapping: Record<string, unknown> | null;

    @Column({ type: 'varchar', length: 60, nullable: true })
    matcherName: string | null;

    @Column({ type: 'jsonb', nullable: true })
    matcherMeta: Record<string, unknown> | null;

    /** Manual overrides are sticky — the resolver never overwrites them. */
    @Column({ type: 'boolean', default: false })
    isManual: boolean;

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;
}

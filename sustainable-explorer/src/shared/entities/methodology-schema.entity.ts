import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    Index,
    Unique,
    CreateDateColumn,
    UpdateDateColumn,
} from 'typeorm';

@Entity('methodology_schema')
@Unique(['topicId', 'schemaUuid'])
@Index(['topicId'])
export class MethodologySchema {
    @PrimaryGeneratedColumn({ type: 'bigint' })
    id: string;

    @Column({ type: 'varchar', length: 30 })
    topicId: string;

    @Column({ type: 'varchar', length: 100 })
    cid: string;

    @Column({ type: 'varchar', length: 255 })
    schemaUuid: string;

    @Column({ type: 'text' })
    iri: string;

    @Column({ type: 'text' })
    name: string;

    @Column({ type: 'text', nullable: true })
    description: string | null;

    @Column({ type: 'jsonb' })
    fields: Record<string, unknown>[];

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;
}
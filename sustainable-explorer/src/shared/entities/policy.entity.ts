import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    Index,
    CreateDateColumn,
    UpdateDateColumn,
} from 'typeorm';

@Entity('policy')
export class Policy {
    @PrimaryGeneratedColumn({ type: 'bigint' })
    id: string;

    @Index({ unique: true })
    @Column({ type: 'varchar', length: 20 })
    instanceTopicId: string;

    @Index()
    @Column({ type: 'varchar', length: 20 })
    policyTopicId: string;

    @Column({ type: 'varchar', length: 30 })
    messageTimestamp: string;

    @Column({ type: 'varchar', length: 100 })
    cid: string;

    @Column({ type: 'varchar', length: 255, nullable: true })
    name: string | null;

    @Column({ type: 'varchar', length: 50, nullable: true })
    version: string | null;

    @Column({ type: 'varchar', length: 100, nullable: true })
    uuid: string | null;

    @Index()
    @Column({ type: 'varchar', length: 200, nullable: true })
    owner: string | null;

    @Column({ type: 'jsonb', nullable: true })
    policyJson: Record<string, unknown> | null;

    @Column({ type: 'jsonb', nullable: true })
    schemas: Record<string, unknown>[] | null;

    @Column({ type: 'jsonb', nullable: true })
    tokens: Record<string, unknown>[] | null;

    @Column({ type: 'varchar', length: 20, default: 'PENDING' })
    status: string;

    @Column({ type: 'text', nullable: true })
    failReason: string | null;

    @Column({ type: 'int', default: 0 })
    retryCount: number;

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;
}

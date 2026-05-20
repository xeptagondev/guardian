import { Entity, Column, PrimaryColumn } from 'typeorm';

@Entity('users')
export class User {
    @PrimaryColumn({ type: 'varchar', length: 200 })
    userDid: string;

    @PrimaryColumn({ type: 'varchar', length: 30 })
    policyTopicId: string;

    @Column({ type: 'varchar', length: 100, nullable: true })
    policyRole: string | null;

    @Column({ type: 'varchar', length: 50, default: 'Unknown' })
    role: string;

    @Column({ type: 'varchar', length: 30 })
    consensusTimeStamp: string;
}
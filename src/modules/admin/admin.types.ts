import { InviteChannel } from '@/modules/auth/auth.types';

export interface InviteUserInput {
    email: string;
    phone?: string;
    roles: string[];
    channel?: InviteChannel;
}

export interface InviteUserResult {
    inviteId: string;
    acceptUrl: string;
    email: string;
    phone?: string;
    channel: InviteChannel;
    expiresAt: Date;
}
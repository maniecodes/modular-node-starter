import { AppError } from '@/core/errors/AppError';
import { generateInviteToken, hashToken } from '@/common/crypto/token';
import { prisma } from '@/core/database/prisma';
import { INVITE_TOKEN_EXPIRY_HOURS } from '@/common/constants';

type CreateUserInviteParams = {
    email: string;
    createdBy: string;
    roleIds: string[];
};

/**
 *  Creates a new user invite with a unique token, stores its hash in the database with an expiry time, and returns the raw token along with invite details. 
 *  This is used to invite new users to the platform by generating a one-time token that can be sent to their email, allowing them to accept the invite and create an account with pre-assigned roles.
 * @param params The parameters for creating the user invite, including email, creator, and role IDs.
 * @returns The invite details including invite ID, raw token, and expiry date.
 */
export async function createUserInvite(params: CreateUserInviteParams): Promise<{
    inviteId: string;
    rawToken: string;
    expiresAt: Date;
}> {
    const rawToken = generateInviteToken();
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + INVITE_TOKEN_EXPIRY_HOURS * 60 * 60 * 1000);

    const invite = await prisma.$transaction(async (tx) => {
        // Invalidate any previously active invite for this email to prevent parallel valid invites.
        await tx.userInvite.updateMany({
            where: {
                email: params.email,
                usedAt: null,
                expiresAt: { gt: new Date() },
            },
            data: { usedAt: new Date() },
        });

        return tx.userInvite.create({
            data: {
                email: params.email,
                tokenHash,
                expiresAt,
                createdBy: params.createdBy,
                userInviteRoles: {
                    createMany: {
                        data: params.roleIds.map((roleId) => ({ roleId })),
                    },
                },
            },
            select: { id: true },
        });
    });

    return { inviteId: invite.id, rawToken, expiresAt };
}
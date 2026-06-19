import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import { OtpPurpose, OtpType } from '@prisma/client';
import { env } from '@/core/config/env';
import { AppError } from '@/core/errors/AppError';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '@/core/auth/jwt';
import {
    exchangeFacebookAuthorizationCode,
    exchangeGoogleAuthorizationCode,
    fetchFacebookProfile,
    verifyGoogleIdToken,
    verifyFacebookAccessToken,
} from '@/core/auth/social-auth-provider.service';
import { securityEvent } from '@/core/audit/security-events';
import { isLocked, recordFailedAttempt, clearAttempts } from '@/core/auth/login-protection';
import { generateOtpCode } from '@/common/crypto/token';
import { sendEmail } from '@/core/mail/mail.service';
import { userInviteTemplate } from '@/core/mail/templates/user-invite.template';
import { logger } from '@/common/utils/logger';
import { SOCIAL_AUTH_PROVIDERS } from '@/common/constants';
import * as authRepository from '@/modules/auth/repositories/auth.repository';
import * as userRepository from '@/modules/users/repositories/users.repository';
import * as adminRepository from '@/modules/admin/repositories/admin.repository';
import {
    InviteUserInput,
    InviteUserResult
} from '@/modules/admin/admin.types';

function buildInviteAcceptUrl(token: string): string {
    const baseUrl = process.env.APP_URL ?? `http://localhost:${env.PORT}`;
    return `${baseUrl}/accept-invite?token=${encodeURIComponent(token)}`;
}

/**
 *  Allows administrators to invite new users to the platform by creating an invitation and sending an email to the invitee.
 * @param input The input containing the invitee's email, phone, roles, and optional invitation channel.
 * @param invitedByUserId The ID of the user who is sending the invitation.
 * @returns An object containing the invitation details, including the invite ID, accept URL, email, phone, channel, and expiration date.
 */
export async function inviteUser(
    input: InviteUserInput,
    invitedByUserId: string,
): Promise<InviteUserResult> {
    const email = input.email.toLowerCase();
    const channel = input.channel ?? 'email';
    if (channel === 'whatsapp' && !input.phone) {
        throw new AppError('Phone is required when invitation channel is WhatsApp', 400);
    }

    const existing = await userRepository.findUserByEmail(email);
    if (existing) throw new AppError('An account with this email already exists', 409);

    const normalizedRoles = [...new Set(input.roles.map((role) => role.trim().toLowerCase()))];
    if (normalizedRoles.length === 0) {
        throw new AppError('At least one role must be selected', 400);
    }

    const selectedRoles = (await userRepository.findRolesByNames(
        normalizedRoles,
    )) as unknown as Array<{ id: string; name: string }>;

    if (selectedRoles.length !== normalizedRoles.length) {
        throw new AppError('One or more selected roles do not exist', 404);
    }

    const inviter = await userRepository.findUserById(invitedByUserId);
    if (!inviter) throw new AppError('Inviter not found', 404);

    const { inviteId, rawToken, expiresAt } = await adminRepository.createUserInvite({
        email,
        createdBy: invitedByUserId,
        roleIds: selectedRoles.map((role) => role.id),
    });

    const acceptUrl = buildInviteAcceptUrl(rawToken);
    const inviterName = `${inviter.firstName} ${inviter.lastName}`.trim();

    // TODO:: implement this later when we have email/whatsapp service setup
    // if (channel === 'email') {
    //   await sendEmail({
    //     to: email,
    //     subject: `${env.APP_NAME} staff invitation`,
    //     html: userInviteTemplate({
    //       appName: env.APP_NAME,
    //       inviteeEmail: email,
    //       invitedBy: inviterName,
    //       acceptUrl,
    //       expiresAt,
    //     }),
    //   });
    // } else {
    //   const message = `You are invited to join ${env.APP_NAME}. Accept invite: ${acceptUrl}`;
    //   logger.info('staff_invite_whatsapp_dispatch', {
    //     phone: input.phone,
    //     email,
    //     invitedByUserId,
    //     message,
    //   });
    // }

    securityEvent('staff_invite_created', {
        actorId: invitedByUserId,
        email,
        channel,
        inviteId,
        roleNames: selectedRoles.map((role) => role.name),
    });

    return {
        inviteId,
        acceptUrl,
        email,
        phone: input.phone,
        channel,
        expiresAt,
    };
}
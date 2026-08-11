import bcrypt from 'bcryptjs';
import { AppError } from '@/core/errors/AppError';
import { env } from '@/core/config/env';
import { OtpPurpose, OtpType, Prisma } from '@prisma/client';
import { OTP_EXPIRY_SKEW_MS, OTP_RESEND_COOLDOWN_MS, MAX_OTP_REQUESTS_PER_WINDOW } from '@/common/constants';
import { generateInviteToken, hashToken, generateFamilyId } from '@/common/crypto/token';
import { prisma } from '@/core/database/prisma';
import { PASSWORD_RESET_TOKEN_EXPIRY_MINUTES, INVITE_TOKEN_EXPIRY_HOURS, SOCIAL_AUTH_PROVIDERS } from '@/common/constants';


type SocialIdentityUserRow = {
  userId: string;
  providerUserId: string;
  providerEmail: string | null;
};

type SocialIdentityRow = {
  userId: string;
  providerUserId: string;
  providerEmail: string | null;
};

/**
 *  Helper function to acquire a PostgreSQL advisory lock for OTP operations. 
 *  This ensures that concurrent requests for the same OTP target/type/purpose are serialized, preventing race conditions.
 * @param tx // Prisma transaction client to execute the lock within
 * @param target // The OTP target (e.g. email or phone number)
 * @param type // The OTP type (e.g. 'EMAIL' or 'SMS')
 * @param purpose // The OTP purpose (e.g. 'REGISTRATION', 'PASSWORD_RESET', etc.)
 */
async function lockOtpScope(
  tx: Prisma.TransactionClient,
  target: string,
  type: OtpType,
  purpose?: OtpPurpose,
): Promise<void> {
  const scopeKey = `otp:${target}:${type}:${purpose ?? 'ANY'}`;
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${scopeKey}))`;
}

export async function findSocialIdentityUser(
  provider: typeof SOCIAL_AUTH_PROVIDERS[0 | 1],
  providerUserId: string,
): Promise<SocialIdentityUserRow | null> {
  const identity = await prisma.authIdentity.findFirst({
    where: {
      provider,
      providerUserId,
    },
    select: {
      userId: true,
      providerUserId: true,
      providerEmail: true,
    },
  });

  return identity;
}

export async function findSocialIdentityByUser(
  provider: typeof SOCIAL_AUTH_PROVIDERS[0 | 1],
  userId: string,
): Promise<SocialIdentityRow | null> {
  const identity = await prisma.authIdentity.findFirst({
    where: {
      provider,
      userId,
    },
    select: {
      userId: true,
      providerUserId: true,
      providerEmail: true,
    },
  });

  return identity;
}

export async function findAuthIdentity(userId: string) {
  return await prisma.authIdentity.findFirst({
    where: {
      userId,
    },
    select: {
      userId: true,
      provider: true,
      providerUserId: true,
      providerEmail: true,
    }
  });
}

export async function linkSocialIdentity(input: {
  provider: typeof SOCIAL_AUTH_PROVIDERS[0 | 1];
  providerUserId: string;
  userId: string;
  providerEmail?: string | null;
}): Promise<void> {
  try {
    await prisma.authIdentity.create({
      data: {
        provider: input.provider,
        providerUserId: input.providerUserId,
        userId: input.userId,
        providerEmail: input.providerEmail ?? null,
      },
    });
  } catch (err: unknown) {
    if ((err as { code?: string }).code !== 'P2002') {
      throw err;
    }

    const linkedIdentity = await findSocialIdentityUser(input.provider, input.providerUserId);
    if (linkedIdentity) {
      if (linkedIdentity.userId === input.userId) {
        return;
      }

      throw new AppError('Social identity is already linked to another account', 409);
    }

    const linkedIdentityForUser = await findSocialIdentityByUser(input.provider, input.userId);
    if (linkedIdentityForUser && linkedIdentityForUser.providerUserId !== input.providerUserId) {
      throw new AppError(`This account is already linked to a different ${input.provider} identity`, 409);
    }

    throw new AppError('Social identity is already linked to another account', 409);
  }
}

/** 
 *  Helper function to find the latest pending OTP for a given target/type/purpose. 
 *  This is used to check if there's an active OTP that can be resent or needs to be consumed.
 * @param target // The target identifier for the OTP (e.g. email or phone number)
 * @param type // The type of OTP (e.g. EMAIL, SMS)
 * @param purpose // The purpose of the OTP (e.g. REGISTRATION, PASSWORD_RESET)
 * @returns // The latest pending OTP record without the code
 */
export async function findLatestPendingOtp(
  target: string,
  type: OtpType,
  purpose?: OtpPurpose,
) {
  return prisma.otpCode.findFirst({
    where: {
      target,
      type,
      purpose,
      usedAt: null,
      invalidatedAt: null,
    },
    orderBy: { createdAt: 'desc' },
    select: {
      target: true,
      type: true,
      purpose: true,
      createdAt: true,
      expiresAt: true,
    },
  });
}

export async function resendOtpCode(
  target: string,
  type: OtpType,
  code: string,
  expiresAt: Date,
  purpose?: OtpPurpose,
  context?: { ipAddress?: string; userAgent?: string },
): Promise<OtpPurpose> {
  return prisma.$transaction(async (tx) => {
    await lockOtpScope(tx, target, type, purpose);

    const now = new Date();
    const latestOtp = await tx.otpCode.findFirst({
      where: {
        target,
        type,
        purpose,
        usedAt: null,
        invalidatedAt: null,
      },
      orderBy: { createdAt: 'desc' },
      select: {
        purpose: true,
        createdAt: true,
        expiresAt: true,
      },
    });

    if (!latestOtp) {
      throw new AppError('No OTP request found for this account', 404);
    }

    const resendPurpose = latestOtp.purpose;
    const windowStart = new Date(now.getTime() - env.OTP_EXPIRES_MINUTES * 60 * 1000);
    const recentRequestCount = await tx.otpCode.count({
      where: {
        target,
        type,
        purpose: resendPurpose,
        createdAt: { gte: windowStart },
      },
    });

    if (recentRequestCount >= MAX_OTP_REQUESTS_PER_WINDOW) {
      throw new AppError('Too many OTP requests. Please try again later.', 429);
    }

    const remainingValidityMs = latestOtp.expiresAt.getTime() - now.getTime();
    if (remainingValidityMs > OTP_EXPIRY_SKEW_MS) {
      const remainingCooldownMs = OTP_RESEND_COOLDOWN_MS - (now.getTime() - latestOtp.createdAt.getTime());
      if (remainingCooldownMs > OTP_EXPIRY_SKEW_MS) {
        throw new AppError(
          `Please wait ${Math.ceil(remainingCooldownMs / 1000)} seconds before requesting another OTP`,
          429,
        );
      }
    }

    await tx.otpCode.updateMany({
      where: {
        target,
        type,
        purpose: resendPurpose,
        usedAt: null,
        invalidatedAt: null,
      },
      data: { invalidatedAt: now },
    });

    await tx.otpCode.create({
      data: {
        target,
        type,
        purpose: resendPurpose,
        code,
        expiresAt,
        requestedIp: context?.ipAddress,
        requestedUserAgent: context?.userAgent,
      },
    });

    return resendPurpose;
  });
}

export async function storeOtpCode(
  target: string,
  type: OtpType,
  purpose: OtpPurpose,
  code: string,
  expiresAt: Date,
  context?: { ipAddress?: string; userAgent?: string },
): Promise<void> {
  await prisma.$transaction(async (tx) => {
    await lockOtpScope(tx, target, type, purpose);

    await tx.otpCode.updateMany({
      where: {
        target, type, purpose, usedAt: null, invalidatedAt: null
      },
      data: { invalidatedAt: new Date() },
    });

    await tx.otpCode.create({
      data: {
        target,
        type,
        purpose,
        code,
        expiresAt,
        requestedIp: context?.ipAddress,
        requestedUserAgent: context?.userAgent,
      },
    });
  });
}

export async function consumeOtpCode(
  target: string,
  type: OtpType,
  purpose: OtpPurpose,
  code: string,
  context?: { ipAddress?: string; userAgent?: string },
): Promise<boolean> {
  return prisma.$transaction(async (tx) => {
    await lockOtpScope(tx, target, type, purpose);

    const now = new Date();
    const record = await tx.otpCode.findFirst({
      where: {
        target,
        type,
        purpose,
        usedAt: null,
        invalidatedAt: null,
        expiresAt: { gt: now },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!record) return false;

    const isCodeValid = await bcrypt.compare(code, record.code);
    if (!isCodeValid) return false;

    // Bind OTP usage to same source context to reduce phishing/replay risk.
    if (record.requestedIp && context?.ipAddress && record.requestedIp !== context.ipAddress) {
      return false;
    }
    if (
      record.requestedUserAgent &&
      context?.userAgent &&
      record.requestedUserAgent !== context.userAgent
    ) {
      return false;
    }

    const result = await tx.otpCode.updateMany({
      where: { id: record.id, usedAt: null, invalidatedAt: null },
      data: { usedAt: now },
    });

    return result.count === 1;
  });
}

// ---------------------------------------------------------------------------
// Refresh token storage (rotation + revocation)
// ---------------------------------------------------------------------------

/** Stores the SHA-256 hash of a raw refresh token. Never stores the raw value.
 * Returns the familyId so the caller can thread it through rotation. */
export async function storeRefreshToken(
  userId: string,
  rawToken: string,
  expiresAt: Date,
  familyId?: string,
  context?: { ipAddress?: string; userAgent?: string },
): Promise<string> {
  const newFamilyId = familyId ?? generateFamilyId();

  await prisma.refreshToken.create({
    data: {
      userId,
      tokenHash: hashToken(rawToken),
      familyId: newFamilyId,
      expiresAt,
      requestedIp: context?.ipAddress ?? null,
      requestedUserAgent: context?.userAgent ?? null,
    },
  });
  return newFamilyId;
}

/**
 * Soft-deletes the token (marks usedAt) and returns { userId, familyId }.
 *
 * Reuse detection: if the token is found but already has usedAt or revokedAt,
 * the entire token family is revoked — a stolen token was replayed.
 *
 * IP binding: if the stored IP differs from the current request IP the token
 * is revoked and null is returned.
 *
 * Returns null in all failure cases; the caller fires the security event.
 */
export async function consumeRefreshToken(
  rawToken: string,
  context?: { ipAddress?: string; userAgent?: string },
): Promise<{ userId: string; familyId: string } | null> {
  const tokenHash = hashToken(rawToken);

  return prisma.$transaction(async (tx) => {
    const record = await tx.refreshToken.findUnique({ where: { tokenHash } });

    if (!record || record.expiresAt < new Date()) return null;

    // Reuse detected: token already consumed or explicitly revoked. N
    // Nuke every active token in the family.
    if (record.usedAt || record.revokedAt) {
      await tx.refreshToken.updateMany({
        where: { familyId: record.familyId, revokedAt: null, usedAt: null },
        data: { revokedAt: new Date() },
      });
      return null;
    }

    if (
      record.requestedIp &&
      context?.ipAddress &&
      record.requestedIp !== context.ipAddress
    ) {
      await tx.refreshToken.update({
        where: { tokenHash },
        data: { revokedAt: new Date() },
      });
      return null;
    }

    await tx.refreshToken.update({
      where: { tokenHash },
      data: { usedAt: new Date() },
    });

    return { userId: record.userId, familyId: record.familyId };
  });
}

/**
 *  Revokes a refresh token by setting its revokedAt timestamp. 
 *  This is used during logout or when a token compromise is suspected to invalidate the token and prevent further use.
 * @param rawToken The raw refresh token to be revoked
 */
export async function revokeRefreshToken(rawToken: string): Promise<void> {
  await prisma.refreshToken.updateMany({
    where: { tokenHash: hashToken(rawToken) },
    data: { revokedAt: new Date() },
  });
}

/**
 *  Revokes all refresh tokens for a given user by setting their revokedAt timestamp. 
 *  This is used when a user changes their password or when a compromise is suspected to invalidate all existing tokens and require re-authentication.
 * @param userId The ID of the user whose refresh tokens are to be revoked.
 */
export async function revokeAllRefreshTokens(userId: string): Promise<void> {
  await prisma.refreshToken.updateMany({
    where: { userId, revokedAt: null, usedAt: null },
    data: { revokedAt: new Date() },
  });
}

// ---------------------------------------------------------------------------
// Password reset token storage
// ---------------------------------------------------------------------------

/**
 *  Generates a secure random token for password reset, stores its hash in the database with an expiry time, and returns the raw token. 
 *  This is used during the forgot password flow to create a one-time token that can be sent to the user's email or phone 
 *  for verification before allowing them to reset their password.
 * @param userId The ID of the user for whom the password reset token is being generated.
 * @param context Optional context information such as IP address and user agent, which can be used for auditing or security purposes.
 * @returns The raw password reset token that can be sent to the user for verification. The hashed version of this token is stored in the database for secure comparison during token consumption.
 */
export async function storePasswordResetToken(
  userId: string,
  context?: { ipAddress?: string; userAgent?: string },
): Promise<string> {
  const { randomBytes } = await import('crypto');
  const rawToken = randomBytes(32).toString('hex');
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(Date.now() + PASSWORD_RESET_TOKEN_EXPIRY_MINUTES * 60 * 1000);

  // Revoke any existing unused tokens for this user first
  await prisma.passwordResetToken.updateMany({
    where: { userId, usedAt: null, revokedAt: null },
    data: { revokedAt: new Date() },
  });

  await prisma.passwordResetToken.create({
    data: {
      userId,
      token: tokenHash,
      expiresAt,
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    },
  });

  return rawToken;
}

/**
 *  Verifies a password reset token by checking if its hash exists in the database, is not expired, and has not been used or revoked. 
 *  If valid, it marks the token as used and returns the associated user ID. 
 *  This is used during the password reset flow to validate the token provided by the user before allowing them to set a new password.
 * @param rawToken The raw password reset token provided by the user. This token will be hashed and compared against the stored hash in the database for verification.
 * @returns The user ID associated with the valid token, or null if the token is invalid, expired, used, or revoked.
 */
export async function consumePasswordResetToken(rawToken: string): Promise<string | null> {
  const tokenHash = hashToken(rawToken);

  return prisma.$transaction(async (tx) => {
    const record = await tx.passwordResetToken.findUnique({ where: { token: tokenHash } });
    if (!record || record.usedAt || record.revokedAt || record.expiresAt < new Date()) {
      return null;
    }
    await tx.passwordResetToken.update({
      where: { id: record.id },
      data: { usedAt: new Date() },
    });
    return record.userId;
  });
}



/**
 *  Verifies a user invite token by checking if its hash exists in the database, is not expired, and has not been used. 
 *  If valid, it marks the invite as used and returns the invite details including email and associated role IDs. 
 *  This is used during the user onboarding flow when accepting an invite to create an account with pre-assigned roles.
 * @param rawToken The raw invite token provided by the user when accepting the invite. This token will be hashed and compared against the stored hash in the database for verification.
 * @returns The invite details including email and associated role IDs, or null if the token is invalid or expired.
 */
export async function consumeUserInvite(rawToken: string): Promise<{
  id: string;
  email: string;
  createdBy: string;
  roleIds: string[];
} | null> {
  const tokenHash = hashToken(rawToken);

  return prisma.$transaction(async (tx) => {
    const now = new Date();
    const invite = await tx.userInvite.findUnique({
      where: { tokenHash },
      include: {
        userInviteRoles: {
          select: { roleId: true },
        },
      },
    });

    if (!invite || invite.usedAt || invite.expiresAt <= now) return null;

    const marked = await tx.userInvite.updateMany({
      where: {
        id: invite.id,
        usedAt: null,
        expiresAt: { gt: now },
      },
      data: { usedAt: now },
    });

    if (marked.count !== 1) return null;

    return {
      id: invite.id,
      email: invite.email,
      createdBy: invite.createdBy,
      roleIds: invite.userInviteRoles.map((r: { roleId: string }) => r.roleId),
    };
  });
}

/**
 *  Helper function to create a new user with assigned roles and an OTP code in a single transaction. 
 *  This is used during registration flows where we want to create the user, assign them default roles, 
 *  and generate an OTP for verification all atomically.
 * @param data // The user data for creating the new user
 * @param roleIds // An array of role IDs to assign to the new user
 * @param otp // The OTP details including target, type, purpose, code, and expiry
 * @param context // Optional context for logging the OTP request (e.g. IP address, user agent)
 * @returns 
 */
export async function createUserWithRolesAndOtp(
  data: {
    firstName: string;
    lastName: string;
    email?: string;
    phone?: string;
    password: string;
  },
  roleIds: string[],
  otp: {
    target: string;
    type: OtpType;
    purpose: OtpPurpose;
    code: string;
    expiresAt: Date;
  },
  context?: { ipAddress?: string; userAgent?: string },
) {
  return prisma.$transaction(async (tx) => {
    await lockOtpScope(tx, otp.target, otp.type, otp.purpose);

    const user = await tx.user.create({
      data,
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        phone: true,
        isVerified: true,
        isEmailVerified: true,
        isPhoneVerified: true,
      },
    });

    await Promise.all(
      roleIds.map((roleId) =>
        tx.userRole.upsert({
          where: { userId_roleId: { userId: user.id, roleId } },
          update: {},
          create: { userId: user.id, roleId, assignedBy: user.id },
        }),
      ),
    );

    await tx.otpCode.updateMany({
      where: {
        target: otp.target,
        type: otp.type,
        purpose: otp.purpose,
        usedAt: null,
        invalidatedAt: null,
      },
      data: { invalidatedAt: new Date() },
    });

    await tx.otpCode.create({
      data: {
        target: otp.target,
        type: otp.type,
        purpose: otp.purpose,
        code: otp.code,
        expiresAt: otp.expiresAt,
        requestedIp: context?.ipAddress,
        requestedUserAgent: context?.userAgent,
      },
    });

    return user;
  });
}

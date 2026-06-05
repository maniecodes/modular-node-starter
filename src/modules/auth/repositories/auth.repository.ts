import { createHash } from 'crypto';
import bcrypt from 'bcryptjs';
import { AppError } from '@/core/errors/AppError';
import { env } from '@/core/config/env';
import { prisma } from '@/core/database/prisma';
import { OtpPurpose, OtpType, Prisma } from '@prisma/client';

const OTP_RESEND_COOLDOWN_MS = 60 * 1000;
const OTP_EXPIRY_SKEW_MS = 5 * 1000;
const MAX_OTP_REQUESTS_PER_WINDOW = 3;

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

async function lockOtpScope(
  tx: Prisma.TransactionClient,
  target: string,
  type: OtpType,
  purpose?: OtpPurpose,
): Promise<void> {
  const scopeKey = `otp:${target}:${type}:${purpose ?? 'ANY'}`;
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${scopeKey}))`;
}

/** Used by login — needs password for bcrypt comparison. */
export async function findUserByEmail(email: string) {
  if (!email) return null;

  return prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      phone: true,
      password: true,
      isActive: true,
      isVerified: true,
      isEmailVerified: true,
      isPhoneVerified: true,
    },
  });
}

export async function findUserByPhone(phone: string) {
  if (!phone) return null;

  return prisma.user.findUnique({
    where: { phone },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      phone: true,
      password: true,
      isActive: true,
      isVerified: true,
      isEmailVerified: true,
      isPhoneVerified: true,
    },
  });
}

/** Used by token refresh — password not needed. */
export async function findUserById(id: string) {
  return prisma.user.findUnique({
    where: { id },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      phone: true,
      isActive: true,
      isEmailVerified: true,
      isPhoneVerified: true,
    },
  });
}

/** Used by registration. Returns the created user without the password field. */
export async function createUser(data: {
  firstName: string;
  lastName: string;
  email?: string;
  phone?: string;
  password: string;
}) {
  return prisma.user.create({
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
}

export async function markUserAsVerified(userId: string, method: OtpType): Promise<void> {
  const data =
    method === OtpType.EMAIL
      ? { isVerified: true, isEmailVerified: true }
      : { isVerified: true, isPhoneVerified: true };

  await prisma.user.update({
    where: { id: userId },
    data,
  });
}

export async function findRolesByNames(names: string[]) {
  return prisma.role.findMany({
    where: { name: { in: names } },
    select: {
      id: true,
      name: true,
      permissions: {
        select: {
          permission: {
            select: { action: true, resource: true },
          },
        },
      },
    },
  });
}

export async function assignRolesToUser(
  userId: string,
  roleIds: string[],
  assignedBy?: string,
): Promise<void> {
  await prisma.$transaction(
    roleIds.map((roleId) =>
      prisma.userRole.upsert({
        where: { userId_roleId: { userId, roleId } },
        update: {},
        create: { userId, roleId, assignedBy },
      }),
    ),
  );
}

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

export async function updateUserPassword(userId: string, hashedPassword: string): Promise<void> {
  await prisma.user.update({
    where: { id: userId },
    data: { password: hashedPassword },
  });
}

export async function findUserRoleNames(userId: string): Promise<string[]> {
  const userRoles = await prisma.userRole.findMany({
    where: { userId },
    select: {
      role: {
        select: { name: true },
      },
    },
  });

  return userRoles.map((ur) => ur.role.name);
}

export async function findUserPermissionKeys(userId: string): Promise<string[]> {
  const userRoles = await prisma.userRole.findMany({
    where: { userId },
    select: {
      role: {
        select: {
          permissions: {
            select: {
              permission: {
                select: { action: true, resource: true },
              },
            },
          },
        },
      },
    },
  });

  return [
    ...new Set(
      userRoles.flatMap((ur) =>
        ur.role.permissions.map((rp) => `${rp.permission.resource}.${rp.permission.action}`),
      ),
    ),
  ];
}

// ---------------------------------------------------------------------------
// Refresh token storage (rotation + revocation)
// ---------------------------------------------------------------------------

/** Stores the SHA-256 hash of a raw refresh token. Never stores the raw value. */
export async function storeRefreshToken(
  userId: string,
  rawToken: string,
  expiresAt: Date,
): Promise<void> {
  await prisma.refreshToken.create({
    data: { userId, tokenHash: hashToken(rawToken), expiresAt },
  });
}

/**
 * Verifies the token exists in DB and hasn't expired, then deletes it
 * atomically. Returns the matching record, or null if not found / expired.
 *
 * Deletion is done in the same operation so a second concurrent request with
 * the same token will fail to find it (the race condition window is reduced to
 * the DB transaction time rather than application round-trip time).
 */
export async function consumeRefreshToken(rawToken: string) {
  const tokenHash = hashToken(rawToken);

  return prisma.$transaction(async (tx) => {
    const record = await tx.refreshToken.findUnique({ where: { tokenHash } });
    if (!record || record.expiresAt < new Date()) return null;
    await tx.refreshToken.delete({ where: { tokenHash } });
    return record;
  });
}

/** Deletes a refresh token by its raw value (used on logout). Idempotent. */
export async function revokeRefreshToken(rawToken: string): Promise<void> {
  await prisma.refreshToken.deleteMany({
    where: { tokenHash: hashToken(rawToken) },
  });
}

/** Deletes all refresh tokens for a user (e.g. logout all devices). */
export async function revokeAllRefreshTokens(userId: string): Promise<void> {
  await prisma.refreshToken.deleteMany({ where: { userId } });
}

// ---------------------------------------------------------------------------
// Password reset token storage
// ---------------------------------------------------------------------------

const PASSWORD_RESET_TOKEN_EXPIRY_MINUTES = 15;

/**
 * Creates a hashed password reset token for the user and stores it in DB.
 * Returns the raw (unhashed) token to be sent to the client.
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
 * Validates a raw reset token by comparing its hash, then marks it as used.
 * Returns the userId if valid, null otherwise.
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

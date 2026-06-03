import { createHash } from 'crypto';
import { prisma } from '@/core/database/prisma';

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/** Used by login — needs password for bcrypt comparison. */
export async function findUserByEmail(email: string) {
  return prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      name: true,
      email: true,
      password: true,
      isActive: true,
    },
  });
}

/** Used by token refresh — password not needed. */
export async function findUserById(id: string) {
  return prisma.user.findUnique({
    where: { id },
    select: {
      id: true,
      name: true,
      email: true,
      isActive: true,
    },
  });
}

/** Used by registration. Returns the created user without the password field. */
export async function createUser(data: { name: string; email: string; password: string }) {
  return prisma.user.create({
    data,
    select: { id: true, name: true, email: true },
  });
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

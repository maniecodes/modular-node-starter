import { Prisma } from '@prisma/client';
import { prisma } from '@/core/database/prisma';
import { AppError } from '@/core/errors/AppError';
import { MAX_ATTEMPTS, WINDOW_MS, LOCKOUT_MS } from '@/common/constants';

async function lockAttemptScope(
  tx: Prisma.TransactionClient,
  identifier: string,
): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`login-attempt:${identifier}`}))`;
}

/**
 * Returns true if the given identifier is currently locked out.
 */
export async function isLocked(identifier: string): Promise<boolean> {
  const record = await prisma.loginAttempt.findUnique({ where: { identifier } });
  if (!record?.lockedUntil) return false;

  if (Date.now() >= record.lockedUntil.getTime()) {
    await prisma.loginAttempt.deleteMany({ where: { identifier } });
    return false;
  }

  return true;
}

/** Records a failed login attempt. Triggers a lockout after MAX_ATTEMPTS. */
export async function recordFailedAttempt(identifier: string): Promise<void> {
  await prisma.$transaction(async (tx) => {
    await lockAttemptScope(tx, identifier);

    const now = new Date();
    const existing = await tx.loginAttempt.findUnique({ where: { identifier } });

    if (!existing || now.getTime() - existing.firstAttemptAt.getTime() > WINDOW_MS) {
      await tx.loginAttempt.upsert({
        where: { identifier },
        update: { count: 1, firstAttemptAt: now, lockedUntil: null },
        create: { identifier, count: 1, firstAttemptAt: now, lockedUntil: null },
      });
      return;
    }

    const nextCount = existing.count + 1;
    await tx.loginAttempt.update({
      where: { identifier },
      data: {
        count: nextCount,
        lockedUntil: nextCount >= MAX_ATTEMPTS ? new Date(now.getTime() + LOCKOUT_MS) : existing.lockedUntil,
      },
    });
  });
}

/** Clears all failed attempt records for an identifier (call on successful login). */
export async function clearAttempts(identifier: string): Promise<void> {
  await prisma.loginAttempt.deleteMany({ where: { identifier } });
}

/** Returns the number of failed attempts recorded for an identifier. */
export async function getAttemptCount(identifier: string): Promise<number> {
  const record = await prisma.loginAttempt.findUnique({ where: { identifier } });
  return record?.count ?? 0;
}

/** Exposed for tests only — resets the entire store. */
export async function _resetStore(): Promise<void> {
  await prisma.loginAttempt.deleteMany();
}

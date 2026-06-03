/**
 * Per-account login attempt tracker with automatic lockout.
 *
 * After MAX_ATTEMPTS consecutive failures within the rolling WINDOW_MS period,
 * the account is locked for LOCKOUT_MS. A successful login clears the record.
 *
 * ⚠️  This is an in-memory implementation. It resets on process restart and
 *      does not work across multiple server instances. For production use at
 *      scale, replace the Map with a Redis-backed store (the interface is
 *      identical — only swapStore() needs changing).
 */

const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

interface AttemptRecord {
  count: number;
  firstAttemptAt: number;
  lockedUntil: number | null;
}

const store = new Map<string, AttemptRecord>();

/**
 * Returns true if the given email is currently locked out.
 * Automatically expires stale lockouts.
 */
export function isLocked(email: string): boolean {
  const record = store.get(email);
  if (!record?.lockedUntil) return false;

  if (Date.now() >= record.lockedUntil) {
    store.delete(email);
    return false;
  }

  return true;
}

/** Records a failed login attempt. Triggers a lockout after MAX_ATTEMPTS. */
export function recordFailedAttempt(email: string): void {
  const now = Date.now();
  const existing = store.get(email);

  if (!existing || now - existing.firstAttemptAt > WINDOW_MS) {
    store.set(email, { count: 1, firstAttemptAt: now, lockedUntil: null });
    return;
  }

  existing.count += 1;

  if (existing.count >= MAX_ATTEMPTS) {
    existing.lockedUntil = now + LOCKOUT_MS;
  }
}

/** Clears all failed attempt records for an email (call on successful login). */
export function clearAttempts(email: string): void {
  store.delete(email);
}

/** Returns the number of failed attempts recorded for an email. */
export function getAttemptCount(email: string): number {
  return store.get(email)?.count ?? 0;
}

/** Exposed for tests only — resets the entire store. */
export function _resetStore(): void {
  store.clear();
}

import { UserContext } from '@/core/auth/user-context';

/**
 * Simple in-memory TTL cache for UserContext objects.
 *
 * Tradeoff: role/permission changes made through the RBAC API will not be
 * visible to in-flight requests until the cached entry expires (TTL_MS).
 * This is intentional — the short window (60 s) is acceptable for most
 * workloads and avoids a DB round-trip on every authenticated request.
 *
 * For immediate revocation (e.g. deactivating a user) call
 * invalidateCachedContext(userId) after writing to the DB.
 *
 * If you need a shared cache across multiple instances, swap the Map for a
 * Redis-backed implementation — the interface here is identical.
 */

const TTL_MS = 60_000; // 1 minute

interface CacheEntry {
  context: UserContext;
  expiresAt: number;
}

const store = new Map<string, CacheEntry>();

export function getCachedContext(userId: string): UserContext | null {
  const entry = store.get(userId);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    store.delete(userId);
    return null;
  }
  return entry.context;
}

export function setCachedContext(userId: string, context: UserContext): void {
  store.set(userId, { context, expiresAt: Date.now() + TTL_MS });
}

/** Call after any operation that changes a user's roles, permissions, or active
 *  state so the next request sees fresh data immediately rather than after TTL. */
export function invalidateCachedContext(userId: string): void {
  store.delete(userId);
}

/** Exposed for use in tests only — clears every entry from the store. */
export function clearContextCache(): void {
  store.clear();
}

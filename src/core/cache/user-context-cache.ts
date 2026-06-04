import { UserContext } from '@/core/auth/user-context';

/**
 * User-context caching is intentionally disabled.
 *
 * The previous in-memory cache introduced cross-instance consistency gaps for
 * authorization-sensitive data. Keeping the interface in place avoids wider
 * call-site churn while forcing fresh reads on every request.
 */

export function getCachedContext(userId: string): UserContext | null {
  return null;
}

export function setCachedContext(userId: string, context: UserContext): void {
  return;
}

/** Call after any operation that changes a user's roles, permissions, or active
 *  state so the next request sees fresh data immediately rather than after TTL. */
export function invalidateCachedContext(userId: string): void {
  return;
}

/** Exposed for use in tests only — clears every entry from the store. */
export function clearContextCache(): void {
  return;
}

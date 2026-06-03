import { loadUserContext } from '@/core/auth/user-context';

/**
 * Returns true if the user is active and has the given permission.
 */
export async function can(userId: string, permission: string): Promise<boolean> {
  const context = await loadUserContext(userId);
  if (!context || !context.isActive) return false;
  return context.permissions.includes(permission);
}

/**
 * Returns true if the user is active and has ALL of the given permissions.
 */
export async function canAll(userId: string, ...permissions: string[]): Promise<boolean> {
  const context = await loadUserContext(userId);
  if (!context || !context.isActive) return false;
  return permissions.every((p) => context.permissions.includes(p));
}

/**
 * Returns true if the user is active and has ANY of the given permissions.
 */
export async function canAny(userId: string, ...permissions: string[]): Promise<boolean> {
  const context = await loadUserContext(userId);
  if (!context || !context.isActive) return false;
  return permissions.some((p) => context.permissions.includes(p));
}

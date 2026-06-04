import { prisma } from '@/core/database/prisma';
import { getCachedContext, setCachedContext } from '@/core/cache/user-context-cache';

export interface UserContext {
  id: string;
  email: string | null;
  phone: string | null;
  isActive: boolean;
  roles: string[];
  permissions: string[];
}

/**
 * Loads a user with all their roles and permissions in a single query.
 * The cache shim is currently disabled so authorization-sensitive reads stay
 * consistent across multiple app instances.
 *
 * Returns null if the user does not exist.
 */
export async function loadUserContext(userId: string): Promise<UserContext | null> {
  const cached = getCachedContext(userId);
  if (cached) return cached;
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      phone: true,
      isActive: true,
      roles: {
        select: {
          role: {
            select: {
              name: true,
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
      },
    },
  });

  if (!user) return null;

  const roles = user.roles.map((ur) => ur.role.name);

  const permissions = [
    ...new Set(
      user.roles.flatMap((ur) =>
        ur.role.permissions.map((rp) => `${rp.permission.resource}.${rp.permission.action}`),
      ),
    ),
  ];

  const context: UserContext = {
    id: user.id,
    email: user.email,
    phone: user.phone,
    isActive: user.isActive,
    roles,
    permissions,
  };
  setCachedContext(userId, context);
  return context;
}

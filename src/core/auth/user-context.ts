import { prisma } from '@/core/database/prisma';

export interface UserContext {
  id: string;
  email: string;
  isActive: boolean;
  roles: string[];
  permissions: string[];
}

/**
 * Loads a user with all their roles and permissions in a single query.
 * Returns null if the user does not exist.
 */
export async function loadUserContext(userId: string): Promise<UserContext | null> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
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

  return { id: user.id, email: user.email, isActive: user.isActive, roles, permissions };
}

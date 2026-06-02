import { prisma } from '@/core/database/prisma';

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

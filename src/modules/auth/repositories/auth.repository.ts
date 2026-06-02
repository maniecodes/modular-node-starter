import { prisma } from '@/core/database/prisma';

export async function findUserByEmail(email: string) {
  return prisma.user.findUnique({ where: { email } });
}

export async function findUserById(id: string) {
  return prisma.user.findUnique({
    where: { id },
    select: { id: true, name: true, email: true },
  });
}

export async function createUser(data: { name: string; email: string; password: string }) {
  return prisma.user.create({
    data,
    select: { id: true, name: true, email: true },
  });
}

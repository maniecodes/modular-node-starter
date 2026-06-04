import { prisma } from '@/core/database/prisma';
import { UpdateUserInput } from '../users.types';

export async function findById(id: string) {
  return prisma.user.findUnique({
    where: { id },
    select: { id: true, firstName: true, lastName: true, email: true, phone: true, createdAt: true },
  });
}

export async function updateById(id: string, data: UpdateUserInput) {
  return prisma.user.update({
    where: { id },
    data,
    select: { id: true, firstName: true, lastName: true, email: true, phone: true, createdAt: true },
  });
}

export async function deleteById(id: string): Promise<void> {
  await prisma.user.delete({ where: { id } });
}

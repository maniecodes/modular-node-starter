// src/modules/users/users.service.ts
import { prisma } from '@/config/database';
import { AppError } from '@/shared/middleware/error.middleware';
import { UpdateUserInput, UserProfile } from './users.types';

export async function getProfile(userId: string): Promise<UserProfile> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, name: true, email: true, createdAt: true },
  });

  if (!user) {
    throw new AppError('User not found', 404);
  }

  return user;
}

export async function updateProfile(userId: string, input: UpdateUserInput): Promise<UserProfile> {
  const user = await prisma.user.findUnique({ where: { id: userId } });

  if (!user) {
    throw new AppError('User not found', 404);
  }

  const updated = await prisma.user.update({
    where: { id: userId },
    data: input,
    select: { id: true, name: true, email: true, createdAt: true },
  });

  return updated;
}



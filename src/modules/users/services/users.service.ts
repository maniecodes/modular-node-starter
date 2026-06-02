import { AppError } from '@/core/errors/AppError';
import * as usersRepository from '../repositories/users.repository';
import { UpdateUserInput, UserProfile } from '../users.types';

export async function getProfile(userId: string): Promise<UserProfile> {
  const user = await usersRepository.findById(userId);
  if (!user) throw new AppError('User not found', 404);
  return user;
}

export async function updateProfile(userId: string, input: UpdateUserInput): Promise<UserProfile> {
  const user = await usersRepository.findById(userId);
  if (!user) throw new AppError('User not found', 404);
  return usersRepository.updateById(userId, input);
}

export async function deleteAccount(userId: string): Promise<void> {
  const user = await usersRepository.findById(userId);
  if (!user) throw new AppError('User not found', 404);
  await usersRepository.deleteById(userId);
}

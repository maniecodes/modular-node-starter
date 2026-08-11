import { Response } from 'express';
import { AuthenticatedRequest } from '@/common/types';
import { sendNoContent, sendSuccess } from '@/common/helpers/response';
import { AppError } from '@/core/errors/AppError';
import * as usersService from '../services/users.service';
import { UpdateUserInput } from '../users.types';

export async function getProfileHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  if (!req.user) throw new AppError('Unauthenticated', 401);
  const user = await usersService.getProfile(req.user.id);
  sendSuccess(res, user, 'Current user retrieved successfully');
}

export async function updateProfileHandler(
  req: AuthenticatedRequest,
  res: Response,
): Promise<void> {
  if (!req.user) throw new AppError('Unauthenticated', 401);
  const updated = await usersService.updateProfile(req.user.id, req.body as UpdateUserInput);
  sendSuccess(res, updated, 'Profile updated');
}

export async function deleteAccountHandler(
  req: AuthenticatedRequest,
  res: Response,
): Promise<void> {
  if (!req.user) throw new AppError('Unauthenticated', 401);
  await usersService.deleteAccount(req.user.id);
  sendNoContent(res);
}

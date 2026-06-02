// src/modules/users/users.controller.ts
import { Response } from 'express';
import { AuthenticatedRequest } from '@/shared/types';
import { sendNoContent, sendSuccess } from '@/shared/utils/response';
import { AppError } from '@/shared/middleware/error.middleware';
import * as usersService from './users.service';
import { UpdateUserInput } from './users.types';

export async function getProfileHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  if (!req.user) throw new AppError('Unauthenticated', 401);
  const user = await usersService.getProfile(req.user.id);
  sendSuccess(res, user);
}

export async function updateProfileHandler(
  req: AuthenticatedRequest,
  res: Response,
): Promise<void> {
  if (!req.user) throw new AppError('Unauthenticated', 401);
  const updated = await usersService.updateProfile(req.user.id, req.body as UpdateUserInput);
  sendSuccess(res, updated, 'Profile updated');
}


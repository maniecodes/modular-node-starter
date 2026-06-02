import { Request, Response } from 'express';
import * as authService from '../services/auth.service';
import { LoginInput, RefreshInput, RegisterInput } from '../auth.types';
import { sendCreated, sendSuccess } from '@/common/helpers/response';

export async function registerHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.register(req.body as RegisterInput);
  sendCreated(res, result, 'Registration successful');
}

export async function loginHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.login(req.body as LoginInput);
  sendSuccess(res, result, 'Login successful');
}

export async function refreshHandler(req: Request, res: Response): Promise<void> {
  const { refreshToken } = req.body as RefreshInput;
  const tokens = await authService.refreshTokens(refreshToken);
  sendSuccess(res, tokens, 'Tokens refreshed');
}

import { Request, Response } from 'express';
import * as authService from '../services/auth.service';
import {
  AcceptInviteInput,
  InviteUserInput,
  LoginInput,
  RefreshInput,
  RegisterInput,
  RequestContext,
  RequestOtpInput,
  VerifyOtpInput,
  ResetPasswordInput,
  VerifyRegistrationOtpInput,
  ResendOtpInput,
} from '../auth.types';
import { AuthenticatedRequest } from '@/common/types';
import { AppError } from '@/core/errors/AppError';
import { sendCreated, sendSuccess } from '@/common/helpers/response';

function getRequestContext(req: Request): RequestContext {
  const forwardedFor = req.headers['x-forwarded-for'];
  const ipFromForwarded = Array.isArray(forwardedFor)
    ? forwardedFor[0]
    : forwardedFor?.split(',')[0]?.trim();

  return {
    ipAddress: ipFromForwarded || req.ip,
    userAgent: req.headers['user-agent'],
  };
}

export async function forgotPasswordHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.forgotPassword(
    req.body as RequestOtpInput,
    getRequestContext(req),
  );
  sendSuccess(res, result, 'Password reset OTP generated');
}

export async function registerHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.register(req.body as RegisterInput, getRequestContext(req));
  sendCreated(res, result, 'Registration successful');
}

export async function loginHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.login(req.body as LoginInput);
  sendSuccess(res, result, 'Login successful');
}

export async function verifyOtpHandler(req: Request, res: Response): Promise<void> {
  const body = req.body as VerifyOtpInput & { purpose: 'REGISTRATION' | 'PASSWORD_RESET' };
  const context = getRequestContext(req);

  if (body.purpose === 'PASSWORD_RESET') {
    const result = await authService.verifyPasswordResetOtp(body, context);
    sendSuccess(res, result, 'OTP verified. Use the reset token to set a new password.');
    return;
  }

  const result = await authService.verifyRegistrationOtp(body as VerifyRegistrationOtpInput, context);
  sendSuccess(res, result, 'Registration OTP verified');
}

export async function resetPasswordHandler(req: Request, res: Response): Promise<void> {
  await authService.resetPassword(req.body as ResetPasswordInput, getRequestContext(req));
  sendSuccess(res, null, 'Password reset successful');
}

export async function refreshHandler(req: Request, res: Response): Promise<void> {
  const { refreshToken } = req.body as RefreshInput;
  const tokens = await authService.refreshTokens(refreshToken);
  sendSuccess(res, tokens, 'Tokens refreshed');
}

export async function resendOtpHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.resendOtp(req.body as RequestOtpInput, getRequestContext(req));
  sendSuccess(res, result, 'OTP resent successfully');
}

export async function inviteUserHandler(
  req: AuthenticatedRequest,
  res: Response,
): Promise<void> {
  if (!req.user) throw new AppError('Unauthenticated', 401);

  const result = await authService.inviteUser(
    req.body as InviteUserInput,
    req.user.id,
  );

  sendCreated(res, result, 'User invitation created');
}

export async function acceptInviteHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.acceptInvite(
    req.body as AcceptInviteInput,
    getRequestContext(req),
  );

  sendSuccess(res, result, 'Invite accepted successfully');
}

export async function logoutHandler(req: Request, res: Response): Promise<void> {
  const { refreshToken } = req.body as RefreshInput;
  await authService.logout(refreshToken);
  sendSuccess(res, null, 'Logged out successfully');
}

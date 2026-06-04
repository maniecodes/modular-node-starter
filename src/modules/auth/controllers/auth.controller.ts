import { Request, Response } from 'express';
import * as authService from '../services/auth.service';
import {
  LoginInput,
  RefreshInput,
  RegisterInput,
  RequestContext,
  RequestOtpInput,
  VerifyOtpInput,
  ResetPasswordInput,
  VerifyRegistrationOtpInput,
} from '../auth.types';
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

export const requestPasswordResetOtpHandler = forgotPasswordHandler;

export async function registerHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.register(req.body as RegisterInput, getRequestContext(req));
  sendCreated(res, result, 'Registration successful');
}

export async function loginHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.login(req.body as LoginInput);
  sendSuccess(res, result, 'Login successful');
}

/**
 * 
 * Handles OTP verification for both registration and password reset flows. For registration, it returns the auth result upon successful OTP verification. For password reset, it performs the password reset immediately upon successful OTP verification.
 * @param req 
 * @param res 
 * @returns 
 */
export async function verifyOtpHandler(req: Request, res: Response): Promise<void> {
  const payload = req.body as VerifyOtpInput;
  const context = getRequestContext(req);

  // For password reset OTP verification, we perform the password reset immediately upon successful OTP verification.
  if (payload.purpose === 'PASSWORD_RESET') {
    await authService.resetPassword(
      {
        email: payload.email,
        phone: payload.phone,
        otpCode: payload.otpCode,
        newPassword: payload.newPassword,
      },
      context,
    );
    sendSuccess(res, null, 'Password reset successful');
    return;
  }

  // For registration OTP verification, we can return the auth result immediately upon successful OTP verification.
  const result = await authService.verifyRegistrationOtp(
    {
      email: payload.email,
      phone: payload.phone,
      otpCode: payload.otpCode,
    } as VerifyRegistrationOtpInput,
    context,
  );
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

export async function logoutHandler(req: Request, res: Response): Promise<void> {
  const { refreshToken } = req.body as RefreshInput;
  await authService.logout(refreshToken);
  sendSuccess(res, null, 'Logged out successfully');
}

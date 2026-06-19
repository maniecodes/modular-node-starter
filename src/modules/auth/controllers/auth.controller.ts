import { Request, Response } from 'express';
import * as authService from '../services/auth.service';
import {
  AcceptInviteInput,
  FacebookLoginInput,
  InviteUserInput,
  LoginInput,
  GoogleLoginInput,
  OAuthCallbackQueryInput,
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

/**
 * Helper function to extract request context information such as IP address and user agent.
 * This context is used for logging, security checks, and other purposes in the authentication service.
 * 
 * @param req Express request object
 * @returns RequestContext containing ipAddress and userAgent
 */
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

/**
 *  Handler for initiating password reset by generating an OTP and sending it to the user's email.
 *  endpoint: POST /api/v1/auth/forgot-password
 * 
 * @param req 
 * @param res 
 */
export async function forgotPasswordHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.forgotPassword(
    req.body as RequestOtpInput,
    getRequestContext(req),
  );
  sendSuccess(res, result, 'Password reset OTP generated');
}

/**
 *  Handler for user registration. It creates a new user account and sends a registration OTP to the user's email or phone for verification.
 *  endpoint: POST /api/v1/auth/register
 * 
 * @param req 
 * @param res 
 */
export async function registerHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.register(req.body as RegisterInput, getRequestContext(req));
  sendCreated(res, result, 'Registration successful');
}

/**
 *  Handler for user login. It authenticates the user and returns access and refresh tokens.
 *  endpoint: POST /api/v1/auth/login
 * 
 * @param req 
 * @param res 
 */
export async function loginHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.login(req.body as LoginInput);
  sendSuccess(res, result, 'Login successful');
}

/**
 *  Handler for Google login. It verifies the Google ID token and returns access and refresh tokens.
 *  endpoint: POST /api/v1/auth/login/google
 *
 * @param req
 * @param res
 */
export async function googleLoginHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.loginWithGoogle(
    req.body as GoogleLoginInput,
    getRequestContext(req),
  );
  sendSuccess(res, result, 'Google login successful');
}

/**
 *  Handler for Facebook login. It verifies the Facebook access token and returns access and refresh tokens.
 *  endpoint: POST /api/v1/auth/login/facebook
 *
 * @param req
 * @param res
 */
export async function facebookLoginHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.loginWithFacebook(
    req.body as FacebookLoginInput,
    getRequestContext(req),
  );
  sendSuccess(res, result, 'Facebook login successful');
}

/**
 *  Handler for Google OAuth callback code exchange.
 *  endpoint: GET /api/v1/auth/callback/google
 */
export async function googleCallbackHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.loginWithGoogleCallback(
    req.query as unknown as OAuthCallbackQueryInput,
    getRequestContext(req),
  );
  sendSuccess(res, result, 'Google callback login successful');
}

/**
 *  Handler for Facebook OAuth callback code exchange.
 *  endpoint: GET /api/v1/auth/callback/facebook
 */
export async function facebookCallbackHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.loginWithFacebookCallback(
    req.query as unknown as OAuthCallbackQueryInput,
    getRequestContext(req),
  );
  sendSuccess(res, result, 'Facebook callback login successful');
}

/**
 *  Handler for verifying OTPs for both registration and password reset purposes. 
 *  It checks the provided OTP against the stored value and, if valid, either completes the registration process or allows the user to proceed with resetting their password.
 *  endpoint: POST /api/v1/auth/verify-otp
 * 
 * @param req 
 * @param res 
 * @returns 
 */
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

/**
 *  Handler for resetting the user's password. It validates the reset token and updates the user's password.
 *  endpoint: POST /api/v1/auth/reset-password
 * 
 * @param req 
 * @param res 
 */
export async function resetPasswordHandler(req: Request, res: Response): Promise<void> {
  await authService.resetPassword(req.body as ResetPasswordInput, getRequestContext(req));
  sendSuccess(res, null, 'Password reset successful');
}

/**
 *  Handler for refreshing authentication tokens. It takes a valid refresh token and returns a new pair of access and refresh tokens.
 *  endpoint: POST /api/v1/auth/refresh
 * 
 * @param req 
 * @param res 
 */
export async function refreshHandler(req: Request, res: Response): Promise<void> {
  const { refreshToken } = req.body as RefreshInput;
  const tokens = await authService.refreshTokens(refreshToken);
  sendSuccess(res, tokens, 'Tokens refreshed');
}

/**
 *  Handler for resending OTPs. It generates a new OTP and sends it to the user's email or phone.
 *  endpoint: POST /api/v1/auth/resend-otp
 * 
 * @param req 
 * @param res 
 */
export async function resendOtpHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.resendOtp(req.body as RequestOtpInput, getRequestContext(req));
  sendSuccess(res, result, 'OTP resent successfully');
}

/**
 *  Handler for accepting a user invitation. 
 *  It validates the invitation token and allows the invitee to set up their account by providing their name and password.
 *  endpoint: POST /api/v1/auth/accept-invite
 * 
 * @param req 
 * @param res 
 */
export async function acceptInviteHandler(req: Request, res: Response): Promise<void> {
  const result = await authService.acceptInvite(
    req.body as AcceptInviteInput,
    getRequestContext(req),
  );

  sendSuccess(res, result, 'Invite accepted successfully');
}

/**
 *  Handler for logging out a user. 
 *  It invalidates the provided refresh token, effectively logging the user out of all sessions that use that token.
 *  endpoint: POST /api/v1/auth/logout
 * 
 * @param req 
 * @param res 
 */
export async function logoutHandler(req: Request, res: Response): Promise<void> {
  const { refreshToken } = req.body as RefreshInput;
  await authService.logout(refreshToken);
  sendSuccess(res, null, 'Logged out successfully');
}

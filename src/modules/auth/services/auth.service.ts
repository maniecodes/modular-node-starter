import bcrypt from 'bcryptjs';
import { OtpPurpose, OtpType } from '@prisma/client';
import { env } from '@/core/config/env';
import { AppError } from '@/core/errors/AppError';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '@/core/auth/jwt';
import { securityEvent } from '@/core/audit/security-events';
import { isLocked, recordFailedAttempt, clearAttempts } from '@/core/auth/login-protection';
import * as authRepository from '../repositories/auth.repository';
import {
  AuthResult,
  AuthUser,
  LoginInput,
  RegisterInput,
  RegisterResult,
  ResendOtpInput,
  RequestContext,
  RequestOtpInput,
  ResetPasswordInput,
  TokenPair,
  VerifyOtpInput,
  VerifyRegistrationOtpInput,
} from '../auth.types';
import { VerifyPasswordResetOtpResult } from '../auth.types';
import { sendSuccess } from '@/common/helpers/response';

type SelectedRole = {
  id: string;
  name: string;
  permissions: Array<{
    permission: {
      resource: string;
      action: string;
    };
  }>;
};

type SafeUserRecord = {
  id: string;
  firstName: string;
  lastName: string;
  email: string | null;
  phone: string | null;
  isVerified: boolean;
  isEmailVerified: boolean;
  isPhoneVerified: boolean;
};


/**
 * Signs a refresh token, stores its hash in DB, and returns the token string.
 * expiresIn is the JWT `exp` unix timestamp returned by verifyRefreshToken.
 */
async function issueRefreshToken(userId: string): Promise<{ token: string; expiresAt: Date }> {
  const token = signRefreshToken(userId);
  // Decode our own token to get the canonical expiry — avoids duplicating the
  // env.JWT_REFRESH_EXPIRES_IN parsing logic here.
  const { exp } = verifyRefreshToken(token);
  const expiresAt = new Date(exp * 1000);
  await authRepository.storeRefreshToken(userId, token, expiresAt);
  return { token, expiresAt };
}

function buildSafeUser(
  user: {
    id: string;
    firstName: string;
    lastName: string;
    email: string | null;
    phone: string | null;
    isEmailVerified: boolean;
    isPhoneVerified: boolean;
  },
  roles: string[] = [],
  permissions: string[] = [],
): AuthUser {
  const verifiedMethods: Array<'EMAIL' | 'PHONE'> = [];
  if (user.isEmailVerified) verifiedMethods.push('EMAIL');
  if (user.isPhoneVerified) verifiedMethods.push('PHONE');

  return {
    id: user.id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    phone: user.phone,
    verifiedMethods,
    roles,
    permissions,
  };
}

function generateOtpCode(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function resolveIdentifier(input: { email?: string; phone?: string }): {
  type: OtpType;
  target: string;
} {
  if (input.email && input.phone) {
    throw new AppError('Provide either email or phone', 400);
  }
  if (input.email) return { type: OtpType.EMAIL, target: input.email.toLowerCase() };
  if (input.phone) return { type: OtpType.PHONE, target: input.phone };
  throw new AppError('Either email or phone is required', 400);
}

async function generateAndStoreOtp(
  target: string,
  type: OtpType,
  purpose: OtpPurpose,
  context?: RequestContext,
): Promise<{ channel: 'email' | 'phone'; otpCode: string }> {

  const code = generateOtpCode();
  const encryptedCode = await bcrypt.hash(code, env.BCRYPT_ROUNDS);
  const expiresAt = new Date(Date.now() + env.OTP_EXPIRES_MINUTES * 60 * 1000);

  await authRepository.storeOtpCode(target, type, purpose, encryptedCode, expiresAt, context);

  return { channel: type === OtpType.EMAIL ? 'email' : 'phone', otpCode: code };
}

async function generateRegistrationOtpPayload(
  target: string,
  type: OtpType,
): Promise<{ otpCode: string; encryptedCode: string; expiresAt: Date }> {
  const otpCode = generateOtpCode();
  const encryptedCode = await bcrypt.hash(otpCode, env.BCRYPT_ROUNDS);
  const expiresAt = new Date(Date.now() + env.OTP_EXPIRES_MINUTES * 60 * 1000);

  return { otpCode, encryptedCode, expiresAt };
}

async function consumeAndValidateOtp(
  input: VerifyOtpInput,
  purpose: OtpPurpose,
  context?: RequestContext,
) {
  const { type, target } = resolveIdentifier(input);
  const otpValid = await authRepository.consumeOtpCode(target, type, purpose, input.otpCode, context);
  if (!otpValid) throw new AppError('Invalid or expired OTP code', 401);

  const user =
    type === OtpType.EMAIL
      ? await authRepository.findUserByEmail(target)
      : await authRepository.findUserByPhone(target);
  if (!user) throw new AppError('Account not found', 404);

  return { user, type };
}

export async function register(
  input: RegisterInput,
  context?: RequestContext,
): Promise<RegisterResult> {
  if (input.email) {
    const existing = await authRepository.findUserByEmail(input.email.toLowerCase());
    if (existing) throw new AppError('Email is already in use', 409);
  }

  if (input.phone) {
    const existing = await authRepository.findUserByPhone(input.phone);
    if (existing) throw new AppError('Phone number is already in use', 409);
  }

  const normalizedRoles = [...new Set(input.roles.map((r) => r.trim().toLowerCase()))];
  if (normalizedRoles.length === 0) {
    throw new AppError('At least one role must be selected', 400);
  }

  const selectedRoles = (await authRepository.findRolesByNames(
    normalizedRoles,
  )) as unknown as SelectedRole[];

  if (selectedRoles.length !== normalizedRoles.length) {
    throw new AppError('One or more selected roles do not exist', 404);
  }

  const hashedPassword = await bcrypt.hash(input.password, env.BCRYPT_ROUNDS);
  const otpTarget = input.email?.toLowerCase() ?? input.phone!;
  const otpType = input.email ? OtpType.EMAIL : OtpType.PHONE;
  const { otpCode, encryptedCode, expiresAt } = await generateRegistrationOtpPayload(
    otpTarget,
    otpType,
  );

  const user = (await authRepository.createUserWithRolesAndOtp(
    {
      firstName: input.firstName,
      lastName: input.lastName,
      email: input.email?.toLowerCase(),
      phone: input.phone,
      password: hashedPassword,
    },
    selectedRoles.map((r) => r.id),
    {
      target: otpTarget,
      type: otpType,
      purpose: OtpPurpose.REGISTRATION,
      code: encryptedCode,
      expiresAt,
    },
    context,
  )) as unknown as SafeUserRecord;

  const roleNames = selectedRoles.map((r) => r.name);
  const permissionKeys = [
    ...new Set(
      selectedRoles.flatMap((r) =>
        r.permissions.map((rp) => `${rp.permission.resource}.${rp.permission.action}`),
      ),
    ),
  ];
  const otpChannel = otpType === OtpType.EMAIL ? 'email' : 'phone';

  securityEvent('register_success', {
    userId: user.id,
    email: user.email,
    phone: user.phone,
    ipAddress: context?.ipAddress,
    userAgent: context?.userAgent,
  });

  return {
    user: buildSafeUser(user, roleNames, permissionKeys),
    requiresOtpVerification: true,
    otpCode,
    otpChannel,
  };
}

export async function login(input: LoginInput, context?: RequestContext): Promise<AuthResult> {
  const identifier = input.email ?? input.phone;
  if (!identifier) throw new AppError('Either email or phone is required', 400);

  // Check lockout before touching the DB — avoids unnecessary load under brute-force
  if (await isLocked(identifier)) {
    securityEvent('login_locked', { identifier });
    throw new AppError('Too many failed login attempts. Please try again later.', 429);
  }

  const user = input.email
    ? await authRepository.findUserByEmail(input.email.toLowerCase())
    : await authRepository.findUserByPhone(input.phone!);

  if (!user) {
    await recordFailedAttempt(identifier);
    securityEvent('login_failure', { identifier, reason: 'user_not_found' });
    throw new AppError('Invalid credentials', 401);
  }

  if (!user.isActive) {
    securityEvent('login_failure', {
      identifier,
      userId: user.id,
      reason: 'account_deactivated',
    });
    throw new AppError('Account is deactivated', 403);
  }

  const isLoginMethodVerified = input.email ? user.isEmailVerified : user.isPhoneVerified;

  if (!isLoginMethodVerified) {
    securityEvent('login_failure', {
      identifier,
      userId: user.id,
      reason: 'account_not_verified',
    });
    await generateAndStoreOtp(
      identifier,
      input.email ? OtpType.EMAIL : OtpType.PHONE,
      OtpPurpose.REGISTRATION,
      context,
    );
    throw new AppError('Please verify this login channel with OTP before logging in', 403);
  }

  const isValid = await bcrypt.compare(input.password, user.password);
  if (!isValid) {
    await recordFailedAttempt(identifier);
    securityEvent('login_failure', {
      identifier,
      userId: user.id,
      reason: 'wrong_password',
    });
    throw new AppError('Invalid credentials', 401);
  }

  await clearAttempts(identifier);

  const roles = await authRepository.findUserRoleNames(user.id);
  const permissions = await authRepository.findUserPermissionKeys(user.id);
  const safeUser = buildSafeUser(user, roles, permissions);
  const { token: refreshToken } = await issueRefreshToken(user.id);
  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email ?? undefined,
    phone: user.phone ?? undefined,
  });

  securityEvent('login_success', { userId: user.id, email: user.email, phone: user.phone });

  return { user: safeUser, tokens: { accessToken, refreshToken } };
}

export async function forgotPassword(
  input: RequestOtpInput,
  context?: RequestContext,
): Promise<{ channel: 'email' | 'phone'; otpCode: string }> {
  const { type, target } = resolveIdentifier(input);
  const user =
    type === OtpType.EMAIL
      ? await authRepository.findUserByEmail(target)
      : await authRepository.findUserByPhone(target);
  if (!user) throw new AppError('Account not found', 404);
  return generateAndStoreOtp(target, type, OtpPurpose.PASSWORD_RESET, context);
}

export async function verifyRegistrationOtp(
  input: VerifyRegistrationOtpInput,
  context?: RequestContext,
): Promise<AuthResult> {
  const { user, type } = await consumeAndValidateOtp(input, OtpPurpose.REGISTRATION, context);

  if (!user.isVerified) {
    await authRepository.markUserAsVerified(user.id, type);
    user.isVerified = true;

    if (type === OtpType.EMAIL) user.isEmailVerified = true;
    else user.isPhoneVerified = true;
  }

  const roles = await authRepository.findUserRoleNames(user.id);
  const permissions = await authRepository.findUserPermissionKeys(user.id);
  const safeUser = buildSafeUser(user, roles, permissions);
  const { token: refreshToken } = await issueRefreshToken(user.id);

  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email ?? undefined,
    phone: user.phone ?? undefined,
  });

  securityEvent('otp_verification_success', {
    userId: user.id,
    email: user.email,
    phone: user.phone,
    ipAddress: context?.ipAddress,
    userAgent: context?.userAgent,
  });

  return { user: safeUser, tokens: { accessToken, refreshToken } };
}

export async function verifyPasswordResetOtp(
  input: VerifyOtpInput,
  context?: RequestContext,
): Promise<VerifyPasswordResetOtpResult> {
  const { user } = await consumeAndValidateOtp(input, OtpPurpose.PASSWORD_RESET, context);

  const resetToken = await authRepository.storePasswordResetToken(user.id, context);

  securityEvent('otp_verification_success', {
    userId: user.id,
    email: user.email,
    phone: user.phone,
    ipAddress: context?.ipAddress,
    userAgent: context?.userAgent,
  });

  return { resetToken };
}

export async function resetPassword(
  input: ResetPasswordInput,
  context?: RequestContext,
): Promise<void> {
  const userId = await authRepository.consumePasswordResetToken(input.resetToken);
  if (!userId) throw new AppError('Invalid or expired password reset token', 401);

  const user = await authRepository.findUserById(userId);
  if (!user) throw new AppError('Account not found', 404);

  const hashedPassword = await bcrypt.hash(input.newPassword, env.BCRYPT_ROUNDS);
  await authRepository.updateUserPassword(user.id, hashedPassword);
  await authRepository.revokeAllRefreshTokens(user.id);

  securityEvent('password_reset_success', {
    userId: user.id,
    email: user.email,
    phone: user.phone,
    ipAddress: context?.ipAddress,
    userAgent: context?.userAgent,
  });
}

export async function resendOtp(
  input: ResendOtpInput,
  context?: RequestContext,
): Promise<{ channel: 'email' | 'phone'; otpCode: string }> {
  const { type, target } = resolveIdentifier(input);
  const otpCode = generateOtpCode();
  const encryptedCode = await bcrypt.hash(otpCode, env.BCRYPT_ROUNDS);
  const expiresAt = new Date(Date.now() + env.OTP_EXPIRES_MINUTES * 60 * 1000);

  const purpose = await authRepository.resendOtpCode(
    target,
    type,
    encryptedCode,
    expiresAt,
    input.purpose as OtpPurpose | undefined,
    context,
  );

  return { channel: type === OtpType.EMAIL ? 'email' : 'phone', otpCode };
}

export async function refreshTokens(rawToken: string): Promise<TokenPair> {
  let payload: { sub: string };
  try {
    payload = verifyRefreshToken(rawToken);
  } catch {
    throw new AppError('Invalid or expired refresh token', 401);
  }

  const record = await authRepository.consumeRefreshToken(rawToken);
  if (!record) {
    securityEvent('refresh_replay_denied', { userId: payload.sub });
    throw new AppError('Refresh token has already been used or revoked', 401);
  }

  const user = await authRepository.findUserById(payload.sub);
  if (!user) throw new AppError('User not found', 401);
  if (!user.isActive) throw new AppError('Account is deactivated', 403);

  const { token: newRefreshToken } = await issueRefreshToken(user.id);
  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email ?? undefined,
    phone: user.phone ?? undefined,
  });

  securityEvent('refresh_success', { userId: user.id });

  return { accessToken, refreshToken: newRefreshToken };
}

export async function logout(rawToken: string): Promise<void> {
  try {
    verifyRefreshToken(rawToken);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : '';
    if (!message.includes('expired')) {
      throw new AppError('Invalid refresh token', 400);
    }
  }
  await authRepository.revokeRefreshToken(rawToken);
  securityEvent('logout_success', {});
}

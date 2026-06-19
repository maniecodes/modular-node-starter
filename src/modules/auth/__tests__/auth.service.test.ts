import bcrypt from 'bcryptjs';
import { AppError } from '@/core/errors/AppError';
import * as authService from '@/modules/auth/services/auth.service';
import * as authRepository from '@/modules/auth/repositories/auth.repository';
import * as userRepository from '@/modules/users/repositories/users.repository';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '@/core/auth/jwt';
import * as loginProtection from '@/core/auth/login-protection';
import * as mailService from '@/core/mail/mail.service';
import * as socialAuthProvider from '@/core/auth/social-auth-provider.service';
import { logger } from '@/common/utils/logger';
import { env } from '@/core/config/env';

// Mock at the repository boundary — service tests must not know Prisma internals
jest.mock('@/modules/auth/repositories/auth.repository');
jest.mock('@/modules/users/repositories/users.repository');
// Mock JWT utility functions directly — avoids reimplementing crypto in tests
jest.mock('@/core/auth/jwt');
jest.mock('bcryptjs');
// Mock login protection so tests run without in-memory state leaking
jest.mock('@/core/auth/login-protection');
jest.mock('@/core/mail/mail.service');
jest.mock('@/core/auth/social-auth-provider.service');
jest.mock('@/common/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

const mockAuthRepo = authRepository as jest.Mocked<typeof authRepository>;
const mockUserRepo = userRepository as jest.Mocked<typeof userRepository>;
const mockSignAccess = signAccessToken as jest.MockedFunction<typeof signAccessToken>;
const mockSignRefresh = signRefreshToken as jest.MockedFunction<typeof signRefreshToken>;
const mockVerifyRefresh = verifyRefreshToken as jest.MockedFunction<typeof verifyRefreshToken>;
const mockBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;
const mockLoginProtection = loginProtection as jest.Mocked<typeof loginProtection>;
const mockMailService = mailService as jest.Mocked<typeof mailService>;
const mockSocialAuthProvider = socialAuthProvider as jest.Mocked<typeof socialAuthProvider>;
const mockLogger = logger as jest.Mocked<typeof logger>;

const sampleUser = {
  id: 'user-1',
  firstName: 'Sam',
  lastName: 'John',
  email: 'sam@gmail.com',
  phone: null,
  isVerified: true,
  isEmailVerified: true,
  isPhoneVerified: false,
};
const dbUserWithPassword = { ...sampleUser, password: 'hashed', isActive: true };
const sampleRole = {
  id: 'role-1',
  name: 'user',
  permissions: [
    {
      permission: { resource: 'users', action: 'read' },
    },
  ],
};
const futureExp = Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60;

const tokenRecord = {
  id: 'rt-1',
  userId: 'user-1',
  tokenHash: 'abc123',
  revokedAt: null,
  expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
  createdAt: new Date(),
};

/** Sets up the mocks needed for issueRefreshToken (called inside register/login/refreshTokens). */
function mockIssueRefreshToken(refreshTokenValue = 'refresh-token') {
  mockSignRefresh.mockReturnValueOnce(refreshTokenValue);
  mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
  mockAuthRepo.storeRefreshToken.mockResolvedValueOnce(undefined as never);
}

beforeEach(() => {
  jest.clearAllMocks();
  // Default: account is not locked — individual tests override this as needed
  mockLoginProtection.isLocked.mockResolvedValue(false);
  (mockBcrypt.hash as jest.Mock).mockResolvedValue('hashed_value');
  env.GOOGLE_CLIENT_ID = 'google-client-id';
  env.GOOGLE_CLIENT_SECRET = 'google-client-secret';
  env.GOOGLE_REDIRECT_URI = 'http://localhost:3000/api/v1/auth/callback/google';
  env.FACEBOOK_APP_ID = 'facebook-app-id';
  env.FACEBOOK_APP_SECRET = 'facebook-app-secret';
  env.FACEBOOK_REDIRECT_URI = 'http://localhost:3000/api/v1/auth/callback/facebook';
});

// ---------------------------------------------------------------------------
// forgotPassword
// ---------------------------------------------------------------------------
describe('authService.forgotPassword', () => {
  it('stores a password reset OTP in the DB', async () => {
    mockUserRepo.findUserByPhone.mockResolvedValueOnce({ ...sampleUser, isVerified: true } as never);

    const result = await authService.forgotPassword({
      phone: '+2348012345678',
    });

    expect(mockAuthRepo.storeOtpCode).toHaveBeenCalledWith(
      '+2348012345678',
      'PHONE',
      'PASSWORD_RESET',
      expect.any(String),
      expect.any(Date),
      undefined,
    );
    expect(result.channel).toBe('phone');
    expect(result.otpCode).toHaveLength(6);
  });

  it('throws 404 when account is not found', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(null);

    await expect(authService.forgotPassword({ email: 'unknown@example.com' })).rejects.toThrow(
      new AppError('Account not found', 404),
    );
  });
});

// ---------------------------------------------------------------------------
// resendOtp
// ---------------------------------------------------------------------------
describe('authService.resendOtp', () => {
  it('throws 429 when a pending OTP is still within the resend cooldown', async () => {
    mockAuthRepo.resendOtpCode.mockRejectedValueOnce(
      new AppError('Please wait 45 seconds before requesting another OTP', 429),
    );

    await expect(authService.resendOtp({ email: 'sam@gmail.com' })).rejects.toThrow(
      new AppError('Please wait 45 seconds before requesting another OTP', 429),
    );
    expect(mockAuthRepo.resendOtpCode).toHaveBeenCalledWith(
      'sam@gmail.com',
      'EMAIL',
      expect.any(String),
      expect.any(Date),
      undefined,
      undefined,
    );
  });

  it('rotates the OTP after the cooldown even when the previous OTP has not expired yet', async () => {
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_otp');
    mockAuthRepo.resendOtpCode.mockResolvedValueOnce('REGISTRATION' as never);

    const result = await authService.resendOtp({ email: 'sam@gmail.com' });

    expect(mockAuthRepo.resendOtpCode).toHaveBeenCalledWith(
      'sam@gmail.com',
      'EMAIL',
      'hashed_otp',
      expect.any(Date),
      undefined,
      undefined,
    );
    expect(result.channel).toBe('email');
    expect(result.otpCode).toHaveLength(6);
  });

  it('forwards the explicit purpose to the repository helper', async () => {
    mockAuthRepo.resendOtpCode.mockResolvedValueOnce('PASSWORD_RESET' as never);

    await authService.resendOtp({ email: 'sam@gmail.com', purpose: 'PASSWORD_RESET' });

    expect(mockAuthRepo.resendOtpCode).toHaveBeenCalledWith(
      'sam@gmail.com',
      'EMAIL',
      expect.any(String),
      expect.any(Date),
      'PASSWORD_RESET',
      undefined,
    );
  });
});

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------
describe('authService.register', () => {
  it('throws 409 when email already exists', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);

    await expect(
      authService.register({
        firstName: 'Sam',
        lastName: 'John',
        email: 'sam@gmail.com',
        roles: ['user'],
        password: 'Password1',
      }),
    ).rejects.toThrow(new AppError('Email is already in use', 409));
  });

  it('hashes the password before storing', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(null);
    mockUserRepo.findRolesByNames.mockResolvedValueOnce([sampleRole] as never);
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_pw');
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_otp');
    mockAuthRepo.createUserWithRolesAndOtp.mockResolvedValueOnce(sampleUser as never);

    await authService.register({
      firstName: 'Sam',
      lastName: 'John',
      email: 'sam@gmail.com',
      roles: ['user'],
      password: 'Password1',
    });

    expect(mockBcrypt.hash).toHaveBeenCalledWith('Password1', expect.any(Number));
    expect(mockBcrypt.hash).toHaveBeenCalledWith(expect.stringMatching(/^\d{6}$/), expect.any(Number));
  });

  it('returns user, requiresOtpVerification and otpCode on success', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(null);
    mockUserRepo.findRolesByNames.mockResolvedValueOnce([sampleRole] as never);
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_pw');
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_otp');
    mockAuthRepo.createUserWithRolesAndOtp.mockResolvedValueOnce(sampleUser as never);

    const result = await authService.register({
      firstName: 'Sam',
      lastName: 'John',
      email: 'sam@gmail.com',
      roles: ['user'],
      password: 'Password1',
    });

    expect(result.user.email).toBe('sam@gmail.com');
    expect(result.user.roles).toEqual(['user']);
    expect(result.user.permissions).toEqual(['users.read']);
    expect(result.requiresOtpVerification).toBe(true);
    expect(result.otpChannel).toBe('email');
    expect(result.otpCode).toHaveLength(6);
    expect(result.user).not.toHaveProperty('password');
    expect(mockAuthRepo.createUserWithRolesAndOtp).toHaveBeenCalledWith(
      {
        firstName: 'Sam',
        lastName: 'John',
        email: 'sam@gmail.com',
        phone: undefined,
        password: 'hashed_pw',
      },
      ['role-1'],
      {
        target: 'sam@gmail.com',
        type: 'EMAIL',
        purpose: 'REGISTRATION',
        code: 'hashed_otp',
        expiresAt: expect.any(Date),
      },
      undefined,
    );
  });

  it('throws 404 when a selected role does not exist', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(null);
    mockUserRepo.findRolesByNames.mockResolvedValueOnce([] as never);

    await expect(
      authService.register({
        firstName: 'Sam',
        lastName: 'John',
        email: 'sam@gmail.com',
        roles: ['missing_role'],
        password: 'Password1',
      }),
    ).rejects.toThrow(new AppError('One or more selected roles do not exist', 404));
  });
});

// ---------------------------------------------------------------------------
// verifyRegistrationOtp
// ---------------------------------------------------------------------------
describe('authService.verifyRegistrationOtp', () => {
  it('verifies user and returns token pair for valid OTP', async () => {
    mockAuthRepo.consumeOtpCode.mockResolvedValueOnce(true);
    mockUserRepo.findUserByEmail.mockResolvedValueOnce({
      ...dbUserWithPassword,
      isVerified: false,
      isEmailVerified: false,
    } as never);
    mockUserRepo.markUserAsVerified.mockResolvedValueOnce(undefined as never);
    mockUserRepo.findUserRoleNames.mockResolvedValueOnce(['user']);
    mockUserRepo.findUserPermissionKeys.mockResolvedValueOnce(['users.read']);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    const result = await authService.verifyRegistrationOtp({
      email: 'sam@gmail.com',
      otpCode: '123456',
    });

    expect(mockUserRepo.markUserAsVerified).toHaveBeenCalledWith('user-1', 'EMAIL');
    expect(result.tokens.accessToken).toBe('access');
    expect(result.tokens.refreshToken).toBe('refresh');
    expect(result.user.verifiedMethods).toEqual(['EMAIL']);
  });

  it('throws 401 for invalid OTP', async () => {
    mockAuthRepo.consumeOtpCode.mockResolvedValueOnce(false);

    await expect(
      authService.verifyRegistrationOtp({
        email: 'sam@gmail.com',
        otpCode: '123456',
      }),
    ).rejects.toThrow(new AppError('Invalid or expired OTP code', 401));
  });
});


// ---------------------------------------------------------------------------
// loginWithGoogle
// ---------------------------------------------------------------------------
describe('authService.loginWithGoogle', () => {
  it('links google identity to an existing email account when not linked yet', async () => {
    mockSocialAuthProvider.verifyGoogleIdToken.mockResolvedValueOnce({
      sub: 'google-sub-123',
      email: 'sam@gmail.com',
      email_verified: true,
      given_name: 'Sam',
      family_name: 'John',
    });

    mockAuthRepo.findSocialIdentityUser.mockResolvedValueOnce(null as never);
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    mockAuthRepo.findSocialIdentityByUser.mockResolvedValueOnce(null as never);
    mockAuthRepo.linkSocialIdentity.mockResolvedValueOnce(undefined as never);
    mockUserRepo.findUserRoleNames.mockResolvedValueOnce(['user']);
    mockUserRepo.findUserPermissionKeys.mockResolvedValueOnce(['users.read']);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    const result = await authService.loginWithGoogle({ idToken: 'google-id-token' });

    expect(mockAuthRepo.linkSocialIdentity).toHaveBeenCalledWith({
      provider: 'google',
      providerUserId: 'google-sub-123',
      userId: 'user-1',
      providerEmail: 'sam@gmail.com',
    });
    expect(result.tokens.accessToken).toBe('access');
    expect(result.tokens.refreshToken).toBe('refresh');
  });

  it('throws 409 when account is already linked to a different google sub', async () => {
    mockSocialAuthProvider.verifyGoogleIdToken.mockResolvedValueOnce({
      sub: 'google-sub-new',
      email: 'sam@gmail.com',
      email_verified: true,
    });

    mockAuthRepo.findSocialIdentityUser.mockResolvedValueOnce(null as never);
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    mockAuthRepo.findSocialIdentityByUser.mockResolvedValueOnce({
      userId: 'user-1',
      providerUserId: 'google-sub-old',
      providerEmail: 'sam@gmail.com',
    } as never);

    await expect(
      authService.loginWithGoogle({ idToken: 'google-id-token' }),
    ).rejects.toThrow(new AppError('This account is already linked to a different google identity', 409));

    expect(mockAuthRepo.linkSocialIdentity).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// loginWithFacebook
// ---------------------------------------------------------------------------
describe('authService.loginWithFacebook', () => {
  it('validates token, links identity, and returns tokens', async () => {
    mockSocialAuthProvider.verifyFacebookAccessToken.mockResolvedValueOnce({
      userId: 'fb-user-123',
      appId: 'facebook-app-id',
      isValid: true,
    });
    mockSocialAuthProvider.fetchFacebookProfile.mockResolvedValueOnce({
      id: 'fb-user-123',
      email: 'sam@gmail.com',
      first_name: 'Sam',
      last_name: 'John',
      name: 'Sam John',
    });

    mockAuthRepo.findSocialIdentityUser.mockResolvedValueOnce(null as never);
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    mockAuthRepo.findSocialIdentityByUser.mockResolvedValueOnce(null as never);
    mockAuthRepo.linkSocialIdentity.mockResolvedValueOnce(undefined as never);
    mockUserRepo.findUserRoleNames.mockResolvedValueOnce(['user']);
    mockUserRepo.findUserPermissionKeys.mockResolvedValueOnce(['users.read']);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    const result = await authService.loginWithFacebook({ accessToken: 'facebook-user-access-token' });

    expect(mockSocialAuthProvider.verifyFacebookAccessToken).toHaveBeenCalledWith({
      userAccessToken: 'facebook-user-access-token',
      appAccessToken: 'facebook-app-id|facebook-app-secret',
    });
    expect(mockSocialAuthProvider.fetchFacebookProfile).toHaveBeenCalledWith('facebook-user-access-token');
    expect(mockAuthRepo.linkSocialIdentity).toHaveBeenCalledWith({
      provider: 'facebook',
      providerUserId: 'fb-user-123',
      userId: 'user-1',
      providerEmail: 'sam@gmail.com',
    });
    expect(result.tokens.accessToken).toBe('access');
    expect(result.tokens.refreshToken).toBe('refresh');
  });

  it('throws 401 when facebook token app_id mismatches configured app', async () => {
    mockSocialAuthProvider.verifyFacebookAccessToken.mockResolvedValueOnce({
      userId: 'fb-user-123',
      appId: 'different-app-id',
      isValid: true,
    });

    await expect(
      authService.loginWithFacebook({ accessToken: 'facebook-user-access-token' }),
    ).rejects.toThrow(new AppError('Facebook token app mismatch', 401));
  });
});

// ---------------------------------------------------------------------------
// loginWithGoogleCallback
// ---------------------------------------------------------------------------
describe('authService.loginWithGoogleCallback', () => {
  it('exchanges code, then logs in with returned id token', async () => {
    mockSocialAuthProvider.exchangeGoogleAuthorizationCode.mockResolvedValueOnce({
      idToken: 'google-id-token-from-code',
    });
    mockSocialAuthProvider.verifyGoogleIdToken.mockResolvedValueOnce({
      sub: 'google-sub-callback',
      email: 'sam@gmail.com',
      email_verified: true,
      given_name: 'Sam',
      family_name: 'John',
    });

    mockAuthRepo.findSocialIdentityUser.mockResolvedValueOnce(null as never);
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    mockAuthRepo.findSocialIdentityByUser.mockResolvedValueOnce(null as never);
    mockAuthRepo.linkSocialIdentity.mockResolvedValueOnce(undefined as never);
    mockUserRepo.findUserRoleNames.mockResolvedValueOnce(['user']);
    mockUserRepo.findUserPermissionKeys.mockResolvedValueOnce(['users.read']);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    const result = await authService.loginWithGoogleCallback({
      code: 'google-auth-code',
      redirectUri: 'http://localhost:3000/api/v1/auth/callback/google',
    });

    expect(mockSocialAuthProvider.exchangeGoogleAuthorizationCode).toHaveBeenCalledWith({
      code: 'google-auth-code',
      clientId: 'google-client-id',
      clientSecret: 'google-client-secret',
      redirectUri: 'http://localhost:3000/api/v1/auth/callback/google',
    });
    expect(result.tokens.accessToken).toBe('access');
    expect(result.tokens.refreshToken).toBe('refresh');
  });
});

// ---------------------------------------------------------------------------
// loginWithFacebookCallback
// ---------------------------------------------------------------------------
describe('authService.loginWithFacebookCallback', () => {
  it('exchanges code, then logs in with returned facebook access token', async () => {
    mockSocialAuthProvider.exchangeFacebookAuthorizationCode.mockResolvedValueOnce({
      accessToken: 'fb-access-token-from-code',
    });
    mockSocialAuthProvider.verifyFacebookAccessToken.mockResolvedValueOnce({
      userId: 'fb-user-callback',
      appId: 'facebook-app-id',
      isValid: true,
    });
    mockSocialAuthProvider.fetchFacebookProfile.mockResolvedValueOnce({
      id: 'fb-user-callback',
      email: 'sam@gmail.com',
      first_name: 'Sam',
      last_name: 'John',
    });

    mockAuthRepo.findSocialIdentityUser.mockResolvedValueOnce(null as never);
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    mockAuthRepo.findSocialIdentityByUser.mockResolvedValueOnce(null as never);
    mockAuthRepo.linkSocialIdentity.mockResolvedValueOnce(undefined as never);
    mockUserRepo.findUserRoleNames.mockResolvedValueOnce(['user']);
    mockUserRepo.findUserPermissionKeys.mockResolvedValueOnce(['users.read']);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    const result = await authService.loginWithFacebookCallback({
      code: 'facebook-auth-code',
      redirectUri: 'http://localhost:3000/api/v1/auth/callback/facebook',
    });

    expect(mockSocialAuthProvider.exchangeFacebookAuthorizationCode).toHaveBeenCalledWith({
      code: 'facebook-auth-code',
      appId: 'facebook-app-id',
      appSecret: 'facebook-app-secret',
      redirectUri: 'http://localhost:3000/api/v1/auth/callback/facebook',
    });
    expect(result.tokens.accessToken).toBe('access');
    expect(result.tokens.refreshToken).toBe('refresh');
  });
});

// ---------------------------------------------------------------------------
// acceptInvite
// ---------------------------------------------------------------------------
describe('authService.acceptInvite', () => {
  it('accepts invite, creates user with roles, and returns auth tokens', async () => {
    mockAuthRepo.consumeUserInvite.mockResolvedValueOnce({
      id: 'invite-1',
      email: 'invited@example.com',
      createdBy: 'user-1',
      roleIds: ['role-1'],
    } as never);
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(null);
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_pw');
    mockUserRepo.createInvitedUserWithRoles.mockResolvedValueOnce({
      id: 'user-2',
      firstName: 'New',
      lastName: 'Staff',
      email: 'invited@example.com',
      phone: null,
      isEmailVerified: true,
      isPhoneVerified: false,
    } as never);
    mockUserRepo.findUserRoleNames.mockResolvedValueOnce(['staff']);
    mockUserRepo.findUserPermissionKeys.mockResolvedValueOnce(['users.read']);
    mockSignRefresh.mockReturnValueOnce('refresh-token');
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-2', exp: futureExp });
    mockAuthRepo.storeRefreshToken.mockResolvedValueOnce(undefined as never);
    mockSignAccess.mockReturnValueOnce('access-token');

    const result = await authService.acceptInvite({
      token: 'raw-token',
      firstName: 'New',
      lastName: 'Staff',
      password: 'Password1',
    });

    expect(mockUserRepo.createInvitedUserWithRoles).toHaveBeenCalledWith({
      firstName: 'New',
      lastName: 'Staff',
      email: 'invited@example.com',
      password: 'hashed_pw',
      roleIds: ['role-1'],
      assignedBy: 'user-1',
    });
    expect(result.tokens.accessToken).toBe('access-token');
    expect(result.tokens.refreshToken).toBe('refresh-token');
  });

  it('throws 401 when invite token is invalid or already used', async () => {
    mockAuthRepo.consumeUserInvite.mockResolvedValueOnce(null as never);

    await expect(
      authService.acceptInvite({
        token: 'invalid-token',
        firstName: 'New',
        lastName: 'Staff',
        password: 'Password1',
      }),
    ).rejects.toThrow(new AppError('Invalid, expired, or already used invite token', 401));
  });
});

// ---------------------------------------------------------------------------
// resetPassword
// ---------------------------------------------------------------------------
describe('authService.resetPassword', () => {
  it('resets password and revokes all sessions when reset token is valid', async () => {
    mockAuthRepo.consumePasswordResetToken.mockResolvedValueOnce('user-1' as never);
    mockUserRepo.findUserById.mockResolvedValueOnce(sampleUser as never);
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('new_hashed_pw');
    mockUserRepo.updateUserPassword.mockResolvedValueOnce(undefined as never);
    mockAuthRepo.revokeAllRefreshTokens.mockResolvedValueOnce(undefined as never);

    await authService.resetPassword({
      resetToken: 'valid-reset-token',
      newPassword: 'NewPassword1',
    });

    expect(mockUserRepo.updateUserPassword).toHaveBeenCalledWith('user-1', 'new_hashed_pw');
    expect(mockAuthRepo.revokeAllRefreshTokens).toHaveBeenCalledWith('user-1');
  });

  it('throws 401 when reset token is invalid or expired', async () => {
    mockAuthRepo.consumePasswordResetToken.mockResolvedValueOnce(null as never);

    await expect(
      authService.resetPassword({
        resetToken: 'invalid-token',
        newPassword: 'NewPassword1',
      }),
    ).rejects.toThrow(new AppError('Invalid or expired password reset token', 401));
  });

  it('throws 404 when account is not found after token check', async () => {
    mockAuthRepo.consumePasswordResetToken.mockResolvedValueOnce('user-1' as never);
    mockUserRepo.findUserById.mockResolvedValueOnce(null as never);

    await expect(
      authService.resetPassword({
        resetToken: 'valid-reset-token',
        newPassword: 'NewPassword1',
      }),
    ).rejects.toThrow(new AppError('Account not found', 404));
  });
});

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------
describe('authService.login', () => {
  it('throws 401 when user not found', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(null);

    await expect(
      authService.login({ email: 'nobody@example.com', password: 'pass' }),
    ).rejects.toThrow(new AppError('Invalid credentials', 401));
  });

  it('throws 403 when account is deactivated', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce({
      ...dbUserWithPassword,
      isActive: false,
    } as never);

    await expect(
      authService.login({ email: 'sam@gmail.com', password: 'Password1' }),
    ).rejects.toThrow(new AppError('Account is deactivated', 403));
  });

  it('throws 403 when account is not verified', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce({
      ...dbUserWithPassword,
      isEmailVerified: false,
    } as never);

    await expect(
      authService.login({ email: 'sam@gmail.com', password: 'Password1' }),
    ).rejects.toThrow(
      new AppError('Please verify this login channel with OTP before logging in', 403),
    );
  });

  it('throws 401 for wrong password', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(false);

    await expect(
      authService.login({ email: 'sam@gmail.com', password: 'wrong' }),
    ).rejects.toThrow(new AppError('Invalid credentials', 401));
  });

  it('returns user (without password) and tokens on valid credentials', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    mockUserRepo.findUserRoleNames.mockResolvedValueOnce(['super_admin']);
    mockUserRepo.findUserPermissionKeys.mockResolvedValueOnce(['users.read', 'roles.assign']);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(true);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    const result = await authService.login({ email: 'sam@gmail.com', password: 'Password1' });

    expect(result.user.email).toBe('sam@gmail.com');
    expect(result.user.roles).toEqual(['super_admin']);
    expect(result.user.permissions).toEqual(['users.read', 'roles.assign']);
    expect(result.user).not.toHaveProperty('password');
    expect(result.user).not.toHaveProperty('isActive');
    expect(result.tokens.accessToken).toBe('access');
  });

  it('stores a new refresh token in the DB on successful login', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    mockUserRepo.findUserRoleNames.mockResolvedValueOnce(['user']);
    mockUserRepo.findUserPermissionKeys.mockResolvedValueOnce(['users.read']);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(true);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    await authService.login({ email: 'sam@gmail.com', password: 'Password1' });

    expect(mockAuthRepo.storeRefreshToken).toHaveBeenCalledWith('user-1', 'refresh', expect.any(Date));
  });

  it('throws 429 when the account is locked out', async () => {
    mockLoginProtection.isLocked.mockResolvedValue(true);

    await expect(
      authService.login({ email: 'sam@gmail.com', password: 'Password1' }),
    ).rejects.toThrow(new AppError('Too many failed login attempts. Please try again later.', 429));

    expect(mockUserRepo.findUserByEmail).not.toHaveBeenCalled();
  });

  it('records a failed attempt when credentials are wrong', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(false);

    await expect(
      authService.login({ email: 'sam@gmail.com', password: 'wrong' }),
    ).rejects.toThrow();

    expect(mockLoginProtection.recordFailedAttempt).toHaveBeenCalledWith('sam@gmail.com');
  });

  it('records a failed attempt when user is not found', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(null);

    await expect(
      authService.login({ email: 'nobody@example.com', password: 'pass' }),
    ).rejects.toThrow();

    expect(mockLoginProtection.recordFailedAttempt).toHaveBeenCalledWith('nobody@example.com');
  });

  it('clears failed attempts on successful login', async () => {
    mockUserRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(true);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    await authService.login({ email: 'sam@gmail.com', password: 'Password1' });

    expect(mockLoginProtection.clearAttempts).toHaveBeenCalledWith('sam@gmail.com');
  });
});

// ---------------------------------------------------------------------------
// refreshTokens
// ---------------------------------------------------------------------------
describe('authService.refreshTokens', () => {
  it('throws 401 for an invalid refresh token (bad signature)', async () => {
    mockVerifyRefresh.mockImplementationOnce(() => {
      throw new Error('invalid signature');
    });

    await expect(authService.refreshTokens('bad-token')).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('throws 401 for an expired refresh token', async () => {
    mockVerifyRefresh.mockImplementationOnce(() => {
      throw new Error('jwt expired');
    });

    await expect(authService.refreshTokens('expired-token')).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('throws 401 when the token has already been consumed (replay prevention)', async () => {
    // JWT is cryptographically valid but was already used — consumeRefreshToken returns null
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockAuthRepo.consumeRefreshToken.mockResolvedValueOnce(null);

    await expect(authService.refreshTokens('already-used-token')).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('rejects a second attempt with the same token (race condition / token reuse)', async () => {
    // First request: succeeds and rotates the token
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockAuthRepo.consumeRefreshToken.mockResolvedValueOnce(tokenRecord);
    mockUserRepo.findUserById.mockResolvedValueOnce({ ...sampleUser, isActive: true } as never);
    mockIssueRefreshToken('new-refresh');
    mockSignAccess.mockReturnValueOnce('new-access');

    await authService.refreshTokens('old-token');

    // Second request with the same old token — DB record is gone
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockAuthRepo.consumeRefreshToken.mockResolvedValueOnce(null);

    await expect(authService.refreshTokens('old-token')).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('throws 401 when user no longer exists', async () => {
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockAuthRepo.consumeRefreshToken.mockResolvedValueOnce(tokenRecord);
    mockUserRepo.findUserById.mockResolvedValueOnce(null);

    await expect(authService.refreshTokens('token')).rejects.toThrow(
      new AppError('User not found', 401),
    );
  });

  it('throws 403 when account is deactivated', async () => {
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockAuthRepo.consumeRefreshToken.mockResolvedValueOnce(tokenRecord);
    mockUserRepo.findUserById.mockResolvedValueOnce({ ...sampleUser, isActive: false } as never);

    await expect(authService.refreshTokens('token')).rejects.toThrow(
      new AppError('Account is deactivated', 403),
    );
  });

  it('issues a rotated token pair on success', async () => {
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockAuthRepo.consumeRefreshToken.mockResolvedValueOnce(tokenRecord);
    mockUserRepo.findUserById.mockResolvedValueOnce({ ...sampleUser, isActive: true } as never);
    mockIssueRefreshToken('new-refresh');
    mockSignAccess.mockReturnValueOnce('new-access');

    const tokens = await authService.refreshTokens('old-token');

    expect(tokens.accessToken).toBe('new-access');
    expect(tokens.refreshToken).toBe('new-refresh');
    // Old token was consumed; a new one was stored
    expect(mockAuthRepo.storeRefreshToken).toHaveBeenCalledWith(
      'user-1',
      'new-refresh',
      expect.any(Date),
    );
  });
});

// ---------------------------------------------------------------------------
// logout
// ---------------------------------------------------------------------------
describe('authService.logout', () => {
  it('revokes the given refresh token', async () => {
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockAuthRepo.revokeRefreshToken.mockResolvedValueOnce(undefined as never);

    await authService.logout('valid-refresh');

    expect(mockAuthRepo.revokeRefreshToken).toHaveBeenCalledWith('valid-refresh');
  });

  it('still revokes an expired token so the client is cleaned up', async () => {
    mockVerifyRefresh.mockImplementationOnce(() => {
      throw new Error('jwt expired');
    });
    mockAuthRepo.revokeRefreshToken.mockResolvedValueOnce(undefined as never);

    await authService.logout('expired-refresh');

    expect(mockAuthRepo.revokeRefreshToken).toHaveBeenCalledWith('expired-refresh');
  });

  it('throws 400 for a completely malformed token', async () => {
    mockVerifyRefresh.mockImplementationOnce(() => {
      throw new Error('invalid signature');
    });

    await expect(authService.logout('not-a-jwt')).rejects.toMatchObject({ statusCode: 400 });
  });
});

import bcrypt from 'bcryptjs';
import { AppError } from '@/core/errors/AppError';
import * as authService from '../services/auth.service';
import * as authRepository from '../repositories/auth.repository';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '@/core/auth/jwt';
import * as loginProtection from '@/core/auth/login-protection';

// Mock at the repository boundary — service tests must not know Prisma internals
jest.mock('../repositories/auth.repository');
// Mock JWT utility functions directly — avoids reimplementing crypto in tests
jest.mock('@/core/auth/jwt');
jest.mock('bcryptjs');
// Mock login protection so tests run without in-memory state leaking
jest.mock('@/core/auth/login-protection');

const mockRepo = authRepository as jest.Mocked<typeof authRepository>;
const mockSignAccess = signAccessToken as jest.MockedFunction<typeof signAccessToken>;
const mockSignRefresh = signRefreshToken as jest.MockedFunction<typeof signRefreshToken>;
const mockVerifyRefresh = verifyRefreshToken as jest.MockedFunction<typeof verifyRefreshToken>;
const mockBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;
const mockLoginProtection = loginProtection as jest.Mocked<typeof loginProtection>;

const sampleUser = {
  id: 'user-1',
  firstName: 'Alice',
  lastName: 'Smith',
  email: 'alice@example.com',
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
  expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
  createdAt: new Date(),
};

/** Sets up the mocks needed for issueRefreshToken (called inside register/login/refreshTokens). */
function mockIssueRefreshToken(refreshTokenValue = 'refresh-token') {
  mockSignRefresh.mockReturnValueOnce(refreshTokenValue);
  mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
  mockRepo.storeRefreshToken.mockResolvedValueOnce(undefined as never);
}

beforeEach(() => {
  jest.clearAllMocks();
  // Default: account is not locked — individual tests override this as needed
  mockLoginProtection.isLocked.mockResolvedValue(false);
  (mockBcrypt.hash as jest.Mock).mockResolvedValue('hashed_value');
});

// ---------------------------------------------------------------------------
// forgotPassword
// ---------------------------------------------------------------------------
describe('authService.forgotPassword', () => {
  it('stores a password reset OTP in the DB', async () => {
    mockRepo.findUserByPhone.mockResolvedValueOnce({ ...sampleUser, isVerified: true } as never);

    const result = await authService.forgotPassword({
      phone: '+2348012345678',
    });

    expect(mockRepo.storeOtpCode).toHaveBeenCalledWith(
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
    mockRepo.findUserByEmail.mockResolvedValueOnce(null);

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
    mockRepo.resendOtpCode.mockRejectedValueOnce(
      new AppError('Please wait 45 seconds before requesting another OTP', 429),
    );

    await expect(authService.resendOtp({ email: 'alice@example.com' })).rejects.toThrow(
      new AppError('Please wait 45 seconds before requesting another OTP', 429),
    );
    expect(mockRepo.resendOtpCode).toHaveBeenCalledWith(
      'alice@example.com',
      'EMAIL',
      expect.any(String),
      expect.any(Date),
      undefined,
      undefined,
    );
  });

  it('rotates the OTP after the cooldown even when the previous OTP has not expired yet', async () => {
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_otp');
    mockRepo.resendOtpCode.mockResolvedValueOnce('REGISTRATION' as never);

    const result = await authService.resendOtp({ email: 'alice@example.com' });

    expect(mockRepo.resendOtpCode).toHaveBeenCalledWith(
      'alice@example.com',
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
    mockRepo.resendOtpCode.mockResolvedValueOnce('PASSWORD_RESET' as never);

    await authService.resendOtp({ email: 'alice@example.com', purpose: 'PASSWORD_RESET' });

    expect(mockRepo.resendOtpCode).toHaveBeenCalledWith(
      'alice@example.com',
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
    mockRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);

    await expect(
      authService.register({
        firstName: 'Alice',
        lastName: 'Smith',
        email: 'alice@example.com',
        roles: ['user'],
        password: 'Password1',
      }),
    ).rejects.toThrow(new AppError('Email is already in use', 409));
  });

  it('hashes the password before storing', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(null);
    mockRepo.findRolesByNames.mockResolvedValueOnce([sampleRole] as never);
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_pw');
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_otp');
    mockRepo.createUserWithRolesAndOtp.mockResolvedValueOnce(sampleUser as never);

    await authService.register({
      firstName: 'Alice',
      lastName: 'Smith',
      email: 'alice@example.com',
      roles: ['user'],
      password: 'Password1',
    });

    expect(mockBcrypt.hash).toHaveBeenCalledWith('Password1', expect.any(Number));
    expect(mockBcrypt.hash).toHaveBeenCalledWith(expect.stringMatching(/^\d{6}$/), expect.any(Number));
  });

  it('returns user, requiresOtpVerification and otpCode on success', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(null);
    mockRepo.findRolesByNames.mockResolvedValueOnce([sampleRole] as never);
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_pw');
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_otp');
    mockRepo.createUserWithRolesAndOtp.mockResolvedValueOnce(sampleUser as never);

    const result = await authService.register({
      firstName: 'Alice',
      lastName: 'Smith',
      email: 'alice@example.com',
      roles: ['user'],
      password: 'Password1',
    });

    expect(result.user.email).toBe('alice@example.com');
    expect(result.user.roles).toEqual(['user']);
    expect(result.user.permissions).toEqual(['users.read']);
    expect(result.requiresOtpVerification).toBe(true);
    expect(result.otpChannel).toBe('email');
    expect(result.otpCode).toHaveLength(6);
    expect(result.user).not.toHaveProperty('password');
    expect(mockRepo.createUserWithRolesAndOtp).toHaveBeenCalledWith(
      {
        firstName: 'Alice',
        lastName: 'Smith',
        email: 'alice@example.com',
        phone: undefined,
        password: 'hashed_pw',
      },
      ['role-1'],
      {
        target: 'alice@example.com',
        type: 'EMAIL',
        purpose: 'REGISTRATION',
        code: 'hashed_otp',
        expiresAt: expect.any(Date),
      },
      undefined,
    );
  });

  it('throws 404 when a selected role does not exist', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(null);
    mockRepo.findRolesByNames.mockResolvedValueOnce([] as never);

    await expect(
      authService.register({
        firstName: 'Alice',
        lastName: 'Smith',
        email: 'alice@example.com',
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
    mockRepo.consumeOtpCode.mockResolvedValueOnce(true);
    mockRepo.findUserByEmail.mockResolvedValueOnce({
      ...dbUserWithPassword,
      isVerified: false,
      isEmailVerified: false,
    } as never);
    mockRepo.markUserAsVerified.mockResolvedValueOnce(undefined as never);
    mockRepo.findUserRoleNames.mockResolvedValueOnce(['user']);
    mockRepo.findUserPermissionKeys.mockResolvedValueOnce(['users.read']);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    const result = await authService.verifyRegistrationOtp({
      email: 'alice@example.com',
      otpCode: '123456',
    });

    expect(mockRepo.markUserAsVerified).toHaveBeenCalledWith('user-1', 'EMAIL');
    expect(result.tokens.accessToken).toBe('access');
    expect(result.tokens.refreshToken).toBe('refresh');
    expect(result.user.verifiedMethods).toEqual(['EMAIL']);
  });

  it('throws 401 for invalid OTP', async () => {
    mockRepo.consumeOtpCode.mockResolvedValueOnce(false);

    await expect(
      authService.verifyRegistrationOtp({
        email: 'alice@example.com',
        otpCode: '123456',
      }),
    ).rejects.toThrow(new AppError('Invalid or expired OTP code', 401));
  });
});

// ---------------------------------------------------------------------------
// resetPassword
// ---------------------------------------------------------------------------
describe('authService.resetPassword', () => {
  it('resets password and revokes all sessions when reset token is valid', async () => {
    mockRepo.consumePasswordResetToken.mockResolvedValueOnce('user-1' as never);
    mockRepo.findUserById.mockResolvedValueOnce(sampleUser as never);
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('new_hashed_pw');
    mockRepo.updateUserPassword.mockResolvedValueOnce(undefined as never);
    mockRepo.revokeAllRefreshTokens.mockResolvedValueOnce(undefined as never);

    await authService.resetPassword({
      resetToken: 'valid-reset-token',
      newPassword: 'NewPassword1',
    });

    expect(mockRepo.updateUserPassword).toHaveBeenCalledWith('user-1', 'new_hashed_pw');
    expect(mockRepo.revokeAllRefreshTokens).toHaveBeenCalledWith('user-1');
  });

  it('throws 401 when reset token is invalid or expired', async () => {
    mockRepo.consumePasswordResetToken.mockResolvedValueOnce(null as never);

    await expect(
      authService.resetPassword({
        resetToken: 'invalid-token',
        newPassword: 'NewPassword1',
      }),
    ).rejects.toThrow(new AppError('Invalid or expired password reset token', 401));
  });

  it('throws 404 when account is not found after token check', async () => {
    mockRepo.consumePasswordResetToken.mockResolvedValueOnce('user-1' as never);
    mockRepo.findUserById.mockResolvedValueOnce(null as never);

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
    mockRepo.findUserByEmail.mockResolvedValueOnce(null);

    await expect(
      authService.login({ email: 'nobody@example.com', password: 'pass' }),
    ).rejects.toThrow(new AppError('Invalid credentials', 401));
  });

  it('throws 403 when account is deactivated', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce({
      ...dbUserWithPassword,
      isActive: false,
    } as never);

    await expect(
      authService.login({ email: 'alice@example.com', password: 'Password1' }),
    ).rejects.toThrow(new AppError('Account is deactivated', 403));
  });

  it('throws 403 when account is not verified', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce({
      ...dbUserWithPassword,
      isEmailVerified: false,
    } as never);

    await expect(
      authService.login({ email: 'alice@example.com', password: 'Password1' }),
    ).rejects.toThrow(
      new AppError('Please verify this login channel with OTP before logging in', 403),
    );
  });

  it('throws 401 for wrong password', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(false);

    await expect(
      authService.login({ email: 'alice@example.com', password: 'wrong' }),
    ).rejects.toThrow(new AppError('Invalid credentials', 401));
  });

  it('returns user (without password) and tokens on valid credentials', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    mockRepo.findUserRoleNames.mockResolvedValueOnce(['super_admin']);
    mockRepo.findUserPermissionKeys.mockResolvedValueOnce(['users.read', 'roles.assign']);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(true);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    const result = await authService.login({ email: 'alice@example.com', password: 'Password1' });

    expect(result.user.email).toBe('alice@example.com');
    expect(result.user.roles).toEqual(['super_admin']);
    expect(result.user.permissions).toEqual(['users.read', 'roles.assign']);
    expect(result.user).not.toHaveProperty('password');
    expect(result.user).not.toHaveProperty('isActive');
    expect(result.tokens.accessToken).toBe('access');
  });

  it('stores a new refresh token in the DB on successful login', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    mockRepo.findUserRoleNames.mockResolvedValueOnce(['user']);
    mockRepo.findUserPermissionKeys.mockResolvedValueOnce(['users.read']);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(true);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    await authService.login({ email: 'alice@example.com', password: 'Password1' });

    expect(mockRepo.storeRefreshToken).toHaveBeenCalledWith('user-1', 'refresh', expect.any(Date));
  });

  it('throws 429 when the account is locked out', async () => {
    mockLoginProtection.isLocked.mockResolvedValue(true);

    await expect(
      authService.login({ email: 'alice@example.com', password: 'Password1' }),
    ).rejects.toThrow(new AppError('Too many failed login attempts. Please try again later.', 429));

    expect(mockRepo.findUserByEmail).not.toHaveBeenCalled();
  });

  it('records a failed attempt when credentials are wrong', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(false);

    await expect(
      authService.login({ email: 'alice@example.com', password: 'wrong' }),
    ).rejects.toThrow();

    expect(mockLoginProtection.recordFailedAttempt).toHaveBeenCalledWith('alice@example.com');
  });

  it('records a failed attempt when user is not found', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(null);

    await expect(
      authService.login({ email: 'nobody@example.com', password: 'pass' }),
    ).rejects.toThrow();

    expect(mockLoginProtection.recordFailedAttempt).toHaveBeenCalledWith('nobody@example.com');
  });

  it('clears failed attempts on successful login', async () => {
    mockRepo.findUserByEmail.mockResolvedValueOnce(dbUserWithPassword as never);
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(true);
    mockIssueRefreshToken('refresh');
    mockSignAccess.mockReturnValueOnce('access');

    await authService.login({ email: 'alice@example.com', password: 'Password1' });

    expect(mockLoginProtection.clearAttempts).toHaveBeenCalledWith('alice@example.com');
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
    mockRepo.consumeRefreshToken.mockResolvedValueOnce(null);

    await expect(authService.refreshTokens('already-used-token')).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('rejects a second attempt with the same token (race condition / token reuse)', async () => {
    // First request: succeeds and rotates the token
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockRepo.consumeRefreshToken.mockResolvedValueOnce(tokenRecord);
    mockRepo.findUserById.mockResolvedValueOnce({ ...sampleUser, isActive: true } as never);
    mockIssueRefreshToken('new-refresh');
    mockSignAccess.mockReturnValueOnce('new-access');

    await authService.refreshTokens('old-token');

    // Second request with the same old token — DB record is gone
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockRepo.consumeRefreshToken.mockResolvedValueOnce(null);

    await expect(authService.refreshTokens('old-token')).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('throws 401 when user no longer exists', async () => {
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockRepo.consumeRefreshToken.mockResolvedValueOnce(tokenRecord);
    mockRepo.findUserById.mockResolvedValueOnce(null);

    await expect(authService.refreshTokens('token')).rejects.toThrow(
      new AppError('User not found', 401),
    );
  });

  it('throws 403 when account is deactivated', async () => {
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockRepo.consumeRefreshToken.mockResolvedValueOnce(tokenRecord);
    mockRepo.findUserById.mockResolvedValueOnce({ ...sampleUser, isActive: false } as never);

    await expect(authService.refreshTokens('token')).rejects.toThrow(
      new AppError('Account is deactivated', 403),
    );
  });

  it('issues a rotated token pair on success', async () => {
    mockVerifyRefresh.mockReturnValueOnce({ sub: 'user-1', exp: futureExp });
    mockRepo.consumeRefreshToken.mockResolvedValueOnce(tokenRecord);
    mockRepo.findUserById.mockResolvedValueOnce({ ...sampleUser, isActive: true } as never);
    mockIssueRefreshToken('new-refresh');
    mockSignAccess.mockReturnValueOnce('new-access');

    const tokens = await authService.refreshTokens('old-token');

    expect(tokens.accessToken).toBe('new-access');
    expect(tokens.refreshToken).toBe('new-refresh');
    // Old token was consumed; a new one was stored
    expect(mockRepo.storeRefreshToken).toHaveBeenCalledWith(
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
    mockRepo.revokeRefreshToken.mockResolvedValueOnce(undefined as never);

    await authService.logout('valid-refresh');

    expect(mockRepo.revokeRefreshToken).toHaveBeenCalledWith('valid-refresh');
  });

  it('still revokes an expired token so the client is cleaned up', async () => {
    mockVerifyRefresh.mockImplementationOnce(() => {
      throw new Error('jwt expired');
    });
    mockRepo.revokeRefreshToken.mockResolvedValueOnce(undefined as never);

    await authService.logout('expired-refresh');

    expect(mockRepo.revokeRefreshToken).toHaveBeenCalledWith('expired-refresh');
  });

  it('throws 400 for a completely malformed token', async () => {
    mockVerifyRefresh.mockImplementationOnce(() => {
      throw new Error('invalid signature');
    });

    await expect(authService.logout('not-a-jwt')).rejects.toMatchObject({ statusCode: 400 });
  });
});

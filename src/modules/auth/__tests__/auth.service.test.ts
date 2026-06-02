// src/modules/auth/__tests__/auth.service.test.ts
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '@/core/database/prisma';
import { AppError } from '@/core/errors/AppError';
import * as authService from '../services/auth.service';

jest.mock('@/core/database/prisma', () => ({
  prisma: {
    user: {
      findUnique: jest.fn(),
      create: jest.fn(),
    },
  },
}));

jest.mock('bcryptjs');
jest.mock('jsonwebtoken');

const mockPrismaUser = prisma.user as jest.Mocked<typeof prisma.user>;
const mockBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;
const mockJwt = jwt as jest.Mocked<typeof jwt>;

const sampleUser = {
  id: 'user-1',
  name: 'Alice',
  email: 'alice@example.com',
};

beforeEach(() => jest.clearAllMocks());

describe('authService.register', () => {
  it('throws 409 when email already exists', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce({
      ...sampleUser,
      password: 'hashed',
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await expect(
      authService.register({ name: 'Alice', email: 'alice@example.com', password: 'Password1' }),
    ).rejects.toThrow(new AppError('Email is already in use', 409));
  });

  it('creates a user and returns tokens', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(null);
    (mockBcrypt.hash as jest.Mock).mockResolvedValueOnce('hashed_pw');
    mockPrismaUser.create.mockResolvedValueOnce(sampleUser as never);
    (mockJwt.sign as jest.Mock).mockReturnValueOnce('access').mockReturnValueOnce('refresh');

    const result = await authService.register({
      name: 'Alice',
      email: 'alice@example.com',
      password: 'Password1',
    });

    expect(result.user.email).toBe('alice@example.com');
    expect(result.tokens.accessToken).toBe('access');
    expect(result.tokens.refreshToken).toBe('refresh');
  });
});

describe('authService.login', () => {
  it('throws 401 when user not found', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(null);

    await expect(
      authService.login({ email: 'nobody@example.com', password: 'pass' }),
    ).rejects.toThrow(new AppError('Invalid credentials', 401));
  });

  it('throws 401 for wrong password', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce({
      ...sampleUser,
      password: 'hashed',
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(false);

    await expect(
      authService.login({ email: 'alice@example.com', password: 'wrong' }),
    ).rejects.toThrow(new AppError('Invalid credentials', 401));
  });

  it('returns user and tokens on valid credentials', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce({
      ...sampleUser,
      password: 'hashed',
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    (mockBcrypt.compare as jest.Mock).mockResolvedValueOnce(true);
    (mockJwt.sign as jest.Mock).mockReturnValueOnce('access').mockReturnValueOnce('refresh');

    const result = await authService.login({
      email: 'alice@example.com',
      password: 'Password1',
    });

    expect(result.user.email).toBe('alice@example.com');
    expect(result.tokens.accessToken).toBe('access');
  });
});

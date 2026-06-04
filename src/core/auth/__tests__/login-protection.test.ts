jest.mock('@/core/database/prisma', () => {
  const mockPrisma = {
    loginAttempt: {
      findUnique: jest.fn(),
      upsert: jest.fn(),
      update: jest.fn(),
      deleteMany: jest.fn(),
    },
    $executeRaw: jest.fn(),
    $transaction: jest.fn(),
  };

  mockPrisma.$transaction.mockImplementation(async (callback: (tx: typeof mockPrisma) => unknown) =>
    callback(mockPrisma),
  );

  return { prisma: mockPrisma };
});

import {
  isLocked,
  recordFailedAttempt,
  clearAttempts,
  getAttemptCount,
  _resetStore,
} from '../login-protection';
import { prisma } from '@/core/database/prisma';

const mockPrisma = prisma as jest.Mocked<typeof prisma>;
const mockTransaction = mockPrisma.$transaction as jest.Mock;
const mockFindUnique = mockPrisma.loginAttempt.findUnique as unknown as jest.Mock;
const mockUpsert = mockPrisma.loginAttempt.upsert as unknown as jest.Mock;
const mockUpdate = mockPrisma.loginAttempt.update as unknown as jest.Mock;
const mockDeleteMany = mockPrisma.loginAttempt.deleteMany as unknown as jest.Mock;

beforeEach(async () => {
  jest.clearAllMocks();
  mockTransaction.mockImplementation(async (callback) => callback(mockPrisma as never));
  mockDeleteMany.mockResolvedValue({ count: 0 } as never);
  await _resetStore();
});

describe('login-protection', () => {
  describe('isLocked', () => {
    it('returns false for an unknown email', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      await expect(isLocked('unknown@example.com')).resolves.toBe(false);
    });

    it('returns false when there is no active lock', async () => {
      mockFindUnique.mockResolvedValueOnce({
        identifier: 'user@example.com',
        count: 2,
        firstAttemptAt: new Date(),
        lockedUntil: null,
        updatedAt: new Date(),
      } as never);

      await expect(isLocked('user@example.com')).resolves.toBe(false);
    });

    it('returns true when lockedUntil is in the future', async () => {
      mockFindUnique.mockResolvedValueOnce({
        identifier: 'user@example.com',
        count: 5,
        firstAttemptAt: new Date(),
        lockedUntil: new Date(Date.now() + 60_000),
        updatedAt: new Date(),
      } as never);

      await expect(isLocked('user@example.com')).resolves.toBe(true);
    });
  });

  describe('recordFailedAttempt', () => {
    it('creates a new record when none exists', async () => {
      mockFindUnique.mockResolvedValueOnce(null);
      mockUpsert.mockResolvedValueOnce({} as never);

      await recordFailedAttempt('user@example.com');

      expect(mockUpsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { identifier: 'user@example.com' },
          create: expect.objectContaining({ identifier: 'user@example.com', count: 1 }),
        }),
      );
    });

    it('increments and locks when threshold is reached', async () => {
      const firstAttemptAt = new Date();
      mockFindUnique.mockResolvedValueOnce({
        identifier: 'user@example.com',
        count: 4,
        firstAttemptAt,
        lockedUntil: null,
        updatedAt: firstAttemptAt,
      } as never);
      mockUpdate.mockResolvedValueOnce({} as never);

      await recordFailedAttempt('user@example.com');

      expect(mockUpdate).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { identifier: 'user@example.com' },
          data: expect.objectContaining({ count: 5, lockedUntil: expect.any(Date) }),
        }),
      );
    });
  });

  describe('clearAttempts', () => {
    it('deletes any stored record for the identifier', async () => {
      mockDeleteMany.mockResolvedValueOnce({ count: 1 } as never);

      await clearAttempts('user@example.com');

      expect(mockDeleteMany).toHaveBeenCalledWith({
        where: { identifier: 'user@example.com' },
      });
    });

    it('is a no-op for an email with no recorded attempts', async () => {
      mockDeleteMany.mockResolvedValueOnce({ count: 0 } as never);

      await expect(clearAttempts('nobody@example.com')).resolves.toBeUndefined();
    });
  });

  describe('getAttemptCount', () => {
    it('returns 0 for an email with no attempts', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      await expect(getAttemptCount('nobody@example.com')).resolves.toBe(0);
    });

    it('returns the stored count for a known identifier', async () => {
      mockFindUnique.mockResolvedValueOnce({
        identifier: 'user@example.com',
        count: 2,
        firstAttemptAt: new Date(),
        lockedUntil: null,
        updatedAt: new Date(),
      } as never);

      await expect(getAttemptCount('user@example.com')).resolves.toBe(2);
    });
  });
});

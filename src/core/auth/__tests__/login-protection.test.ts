import {
  isLocked,
  recordFailedAttempt,
  clearAttempts,
  getAttemptCount,
  _resetStore,
} from '../login-protection';

beforeEach(() => _resetStore());

describe('login-protection', () => {
  describe('isLocked', () => {
    it('returns false for an unknown email', () => {
      expect(isLocked('unknown@example.com')).toBe(false);
    });

    it('returns false when fewer than 5 attempts have been recorded', () => {
      recordFailedAttempt('user@example.com');
      recordFailedAttempt('user@example.com');
      expect(isLocked('user@example.com')).toBe(false);
    });

    it('returns true after exactly 5 failed attempts', () => {
      for (let i = 0; i < 5; i++) {
        recordFailedAttempt('user@example.com');
      }
      expect(isLocked('user@example.com')).toBe(true);
    });

    it('returns true after more than 5 failed attempts', () => {
      for (let i = 0; i < 7; i++) {
        recordFailedAttempt('user@example.com');
      }
      expect(isLocked('user@example.com')).toBe(true);
    });
  });

  describe('recordFailedAttempt', () => {
    it('increments the attempt count', () => {
      recordFailedAttempt('user@example.com');
      recordFailedAttempt('user@example.com');
      expect(getAttemptCount('user@example.com')).toBe(2);
    });

    it('treats each email independently', () => {
      recordFailedAttempt('a@example.com');
      recordFailedAttempt('b@example.com');
      recordFailedAttempt('b@example.com');

      expect(getAttemptCount('a@example.com')).toBe(1);
      expect(getAttemptCount('b@example.com')).toBe(2);
    });
  });

  describe('clearAttempts', () => {
    it('resets the attempt count to zero', () => {
      recordFailedAttempt('user@example.com');
      recordFailedAttempt('user@example.com');
      clearAttempts('user@example.com');

      expect(getAttemptCount('user@example.com')).toBe(0);
      expect(isLocked('user@example.com')).toBe(false);
    });

    it('unlocks an account that had been locked', () => {
      for (let i = 0; i < 5; i++) {
        recordFailedAttempt('user@example.com');
      }
      expect(isLocked('user@example.com')).toBe(true);

      clearAttempts('user@example.com');
      expect(isLocked('user@example.com')).toBe(false);
    });

    it('is a no-op for an email with no recorded attempts', () => {
      expect(() => clearAttempts('nobody@example.com')).not.toThrow();
    });
  });

  describe('getAttemptCount', () => {
    it('returns 0 for an email with no attempts', () => {
      expect(getAttemptCount('nobody@example.com')).toBe(0);
    });
  });
});

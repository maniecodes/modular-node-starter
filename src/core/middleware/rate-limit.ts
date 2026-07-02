import rateLimit from 'express-rate-limit';

const rateLimitMessage = (message: string) => ({
  success: false,
  message,
});

/**
 * Applied to all /api/v1/* routes.
 * 100 requests per 15-minute window per IP.
 */
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: rateLimitMessage('Too many requests — please try again later.'),
});

/**
 * Applied to /auth/refresh only.
 * Max 5 refresh calls per minute per IP — burst rotation is a strong signal of theft.
 */
export const refreshLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: rateLimitMessage('Too many token refresh attempts — please try again later.'),
});

/**
 * Applied to auth routes only (login, register, logout).
 * Stricter: 10 attempts per 15-minute window per IP.
 * Prevents brute-force and credential stuffing attacks.
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: rateLimitMessage('Too many authentication attempts — please try again later.'),
});


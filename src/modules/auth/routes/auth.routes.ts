import { Router } from 'express';
import { validate } from '@/core/middleware/validate.middleware';
import { requireAuth } from '@/core/middleware/auth.middleware';
import {
  acceptInviteSchema,
  facebookLoginSchema,
  forgotPasswordSchema,
  googleLoginSchema,
  loginSchema,
  oauthCallbackQuerySchema,
  logoutSchema,
  refreshSchema,
  registerSchema,
  resendOtpSchema,
  resetPasswordSchema,
  verifyOtpSchema,
} from '../validators/auth.validator';
import {
  acceptInviteHandler,
  facebookCallbackHandler,
  facebookLoginHandler,
  googleCallbackHandler,
  loginHandler,
  logoutHandler,
  forgotPasswordHandler,
  googleLoginHandler,
  refreshHandler,
  registerHandler,
  resendOtpHandler,
  resetPasswordHandler,
  verifyOtpHandler,
} from '../controllers/auth.controller';

const router = Router();


router.post('/login', validate(loginSchema), loginHandler);
router.post('/login/google', validate(googleLoginSchema), googleLoginHandler);
router.get('/callback/google', validate(oauthCallbackQuerySchema, 'query'), googleCallbackHandler);
router.post('/login/facebook', validate(facebookLoginSchema), facebookLoginHandler);
router.get('/callback/facebook', validate(oauthCallbackQuerySchema, 'query'), facebookCallbackHandler);
router.post('/logout', requireAuth, validate(logoutSchema), logoutHandler);
router.post('/forgot-password', validate(forgotPasswordSchema), forgotPasswordHandler);
router.post('/refresh', validate(refreshSchema), refreshHandler);
router.post('/register', validate(registerSchema), registerHandler);
router.post('/accept-invite', validate(acceptInviteSchema), acceptInviteHandler);
router.post('/resend-otp', validate(resendOtpSchema), resendOtpHandler);
router.post('/reset-password', validate(resetPasswordSchema), resetPasswordHandler);
router.post('/verify-otp', validate(verifyOtpSchema), verifyOtpHandler);

export default router;

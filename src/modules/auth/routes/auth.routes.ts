import { Router } from 'express';
import { validate } from '@/core/validation/validate.middleware';
import {
  forgotPasswordSchema,
  loginSchema,
  logoutSchema,
  refreshSchema,
  registerSchema,
  resendOtpSchema,
  resetPasswordSchema,
  verifyOtpSchema,
} from '../validators/auth.validator';
import {
  loginHandler,
  logoutHandler,
  forgotPasswordHandler,
  refreshHandler,
  registerHandler,
  resendOtpHandler,
  resetPasswordHandler,
  verifyOtpHandler,
} from '../controllers/auth.controller';

const router = Router();


router.post('/login', validate(loginSchema), loginHandler);
router.post('/logout', validate(logoutSchema), logoutHandler);
router.post('/forgot-password', validate(forgotPasswordSchema), forgotPasswordHandler);
router.post('/refresh', validate(refreshSchema), refreshHandler);
router.post('/register', validate(registerSchema), registerHandler);
router.post('/resend-otp', validate(resendOtpSchema), resendOtpHandler);
router.post('/reset-password', validate(resetPasswordSchema), resetPasswordHandler);
router.post('/verify-otp', validate(verifyOtpSchema), verifyOtpHandler);

export default router;

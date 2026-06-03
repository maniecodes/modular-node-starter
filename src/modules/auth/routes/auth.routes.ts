import { Router } from 'express';
import { validate } from '@/core/validation/validate.middleware';
import {
  loginSchema,
  logoutSchema,
  refreshSchema,
  registerSchema,
} from '../validators/auth.validator';
import {
  loginHandler,
  logoutHandler,
  refreshHandler,
  registerHandler,
} from '../controllers/auth.controller';

const router = Router();

router.post('/register', validate(registerSchema), registerHandler);
router.post('/login', validate(loginSchema), loginHandler);
router.post('/refresh', validate(refreshSchema), refreshHandler);
router.post('/logout', validate(logoutSchema), logoutHandler);

export default router;

// src/modules/auth/auth.routes.ts
import { Router } from 'express';
import { validate } from '@/shared/middleware/validate.middleware';
import { loginSchema, refreshSchema, registerSchema } from './auth.validation';
import { loginHandler, refreshHandler, registerHandler } from './auth.controller';

const router = Router();

router.post('/register', validate(registerSchema), registerHandler);
router.post('/login', validate(loginSchema), loginHandler);
router.post('/refresh', validate(refreshSchema), refreshHandler);

export default router;

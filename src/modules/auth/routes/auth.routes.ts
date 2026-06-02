import { Router } from 'express';
import { validate } from '@/core/validation/validate.middleware';
import { loginSchema, refreshSchema, registerSchema } from '../validators/auth.validator';
import { loginHandler, refreshHandler, registerHandler } from '../controllers/auth.controller';

const router = Router();

router.post('/register', validate(registerSchema), registerHandler);
router.post('/login', validate(loginSchema), loginHandler);
router.post('/refresh', validate(refreshSchema), refreshHandler);

export default router;

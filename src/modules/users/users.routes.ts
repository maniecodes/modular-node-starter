// src/modules/users/users.routes.ts
import { Router } from 'express';
import { requireAuth } from '@/shared/middleware/auth.middleware';
import { validate } from '@/shared/middleware/validate.middleware';
import { updateUserSchema } from './users.validation';
import { deleteAccountHandler, getProfileHandler, updateProfileHandler } from './users.controller';
import { AuthenticatedRequest } from '@/shared/types';
import { Response, NextFunction } from 'express';

const router = Router();

// Cast to satisfy Express typings with AuthenticatedRequest
type AuthHandler = (req: AuthenticatedRequest, res: Response, next: NextFunction) => Promise<void>;
const wrap =
  (fn: AuthHandler) =>
  (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    fn(req, res, next).catch(next);
  };

router.use(requireAuth);

router.get('/me', wrap(getProfileHandler));
router.patch('/me', validate(updateUserSchema), wrap(updateProfileHandler));
router.delete('/me', wrap(deleteAccountHandler));

export default router;

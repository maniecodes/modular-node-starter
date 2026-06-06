import { Router } from 'express';
import { Response, NextFunction } from 'express';
import { requireAuth } from '@/core/middleware/auth.middleware';
import { validate } from '@/core/middleware/validate.middleware';
import { updateUserSchema } from '../validators/users.validator';
import {
  deleteAccountHandler,
  getProfileHandler,
  updateProfileHandler,
} from '../controllers/users.controller';
import { AuthenticatedRequest } from '@/common/types';

const router = Router();

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

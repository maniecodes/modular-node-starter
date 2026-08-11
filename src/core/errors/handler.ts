import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { logger } from '@/common/utils/logger';
import { sendError } from '@/common/helpers/response';
import { AppError } from './AppError';

export function errorHandler(err: Error, _req: Request, res: Response, _next: NextFunction): void {
  if (err instanceof ZodError) {
    sendError(res, 'Validation failed', 422, err.flatten().fieldErrors);
    return;
  }

  if (err instanceof AppError) {
    sendError(res, err.message, err.statusCode);
    return;
  }

  logger.error('Unhandled error', { message: err.message, stack: err.stack });
  sendError(res, 'Internal server error', 500);
}

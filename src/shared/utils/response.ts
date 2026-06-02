// src/shared/utils/response.ts
import { Response } from 'express';
import { ApiResponse } from '@/shared/types';

export function sendSuccess<T>(
  res: Response,
  data: T,
  message = 'Success',
  statusCode = 200,
): void {
  const response: ApiResponse<T> = { success: true, message, data };
  res.status(statusCode).json(response);
}

export function sendCreated<T>(res: Response, data: T, message = 'Created'): void {
  sendSuccess(res, data, message, 201);
}

export function sendNoContent(res: Response): void {
  res.status(204).send();
}

export function sendError(
  res: Response,
  message: string,
  statusCode = 500,
  errors?: unknown,
): void {
  const response: ApiResponse = { success: false, message, errors };
  res.status(statusCode).json(response);
}

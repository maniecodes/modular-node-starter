// src/app.ts
import 'express-async-errors';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';

import { env } from '@/config/env';
import { errorMiddleware } from '@/shared/middleware/error.middleware';
import { sendSuccess } from '@/shared/utils/response';

import authRoutes from '@/modules/auth/auth.routes';
import usersRoutes from '@/modules/users/users.routes';

const app = express();

// Security & parsing
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// HTTP logging (skip in test)
if (env.NODE_ENV !== 'test') {
  app.use(morgan(env.NODE_ENV === 'production' ? 'combined' : 'dev'));
}

// Health check
app.get('/health', (_req, res) => {
  sendSuccess(res, { status: 'ok', timestamp: new Date().toISOString() });
});

// Module routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/users', usersRoutes);

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// Global error handler (must be last)
app.use(errorMiddleware);

export default app;

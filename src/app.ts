// src/app.ts
import 'express-async-errors';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';

import { env } from '@/core/config/env';
import { errorHandler } from '@/core/errors/handler';
import { apiLimiter, authLimiter } from '@/core/middleware/rate-limit';
import { sendSuccess } from '@/common/helpers/response';

import authRoutes from '@/modules/auth/routes/auth.routes';
import adminRoutes from '@/modules/auth/routes/admin.routes';
import usersRoutes from '@/modules/users/routes/users.routes';
import { rolesRouter, permissionsRouter } from '@/modules/roles/routes/roles.routes';

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
app.use('/api/v1/auth', authLimiter, authRoutes);
app.use('/api/v1/admin', apiLimiter, adminRoutes);
app.use('/api/v1/users', apiLimiter, usersRoutes);
app.use('/api/v1/roles', apiLimiter, rolesRouter);
app.use('/api/v1/permissions', apiLimiter, permissionsRouter);

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// Global error handler (must be last)
app.use(errorHandler);

export default app;

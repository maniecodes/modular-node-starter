// src/server.ts
import app from './app';
import { env } from '@/core/config/env';
import { prisma } from '@/core/database/prisma';
import { logger } from '@/common/utils/logger';

async function bootstrap(): Promise<void> {
  await prisma.$connect();
  logger.info('Database connection established');

  const server = app.listen(env.PORT, () => {
    logger.info(`Server running on http://localhost:${env.PORT} [${env.NODE_ENV}]`);
  });

  const shutdown = async (signal: string): Promise<void> => {
    logger.info(`${signal} received — shutting down gracefully`);
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await prisma.$disconnect();
    logger.info('Database disconnected. Bye!');
    process.exit(0);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

bootstrap().catch((err: unknown) => {
  logger.error('Fatal error during bootstrap', err);
  process.exit(1);
});

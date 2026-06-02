// src/server.ts
import app from './app';
import { env } from '@/config/env';
import { prisma } from '@/config/database';
import { logger } from '@/shared/utils/logger';

async function bootstrap(): Promise<void> {
  await prisma.$connect();
  logger.info('Database connection established');

  const server = app.listen(env.PORT, () => {
    logger.info(`Server running on http://localhost:${env.PORT} [${env.NODE_ENV}]`);
  });

  const shutdown = async (signal: string): Promise<void> => {
    logger.info(`${signal} received — shutting down gracefully`);
    server.close(async () => {
      await prisma.$disconnect();
      logger.info('Database disconnected. Bye!');
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

bootstrap().catch((err: unknown) => {
  logger.error('Fatal error during bootstrap', err);
  process.exit(1);
});

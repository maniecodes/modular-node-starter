import { prisma } from '@/core/database/prisma';

export interface AuditLogEntry {
  event: string;
  actorId?: string;
  targetId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Writes a structured audit record to the database.
 * This is a fire-and-forget helper — callers should `.catch()` it so that a
 * failed audit write never blocks the main operation.
 */
export async function writeAuditLog(entry: AuditLogEntry): Promise<void> {
  await prisma.auditLog.create({
    data: {
      event: entry.event,
      actorId: entry.actorId,
      targetId: entry.targetId,
      metadata: entry.metadata ?? undefined,
    },
  });
}

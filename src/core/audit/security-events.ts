import { env } from '@/core/config/env';

export type SecurityEventType =
  | 'login_success'
  | 'login_failure'
  | 'login_locked'
  | 'register_success'
  | 'refresh_success'
  | 'refresh_replay_denied'
  | 'logout_success'
  | 'role_assigned'
  | 'role_revoked'
  | 'permission_assigned'
  | 'permission_revoked'
  | 'authorization_denied';

/**
 * Emits a structured security audit event to stdout as newline-delimited JSON.
 * In production, pipe stdout to your log aggregator (CloudWatch, Datadog, etc.).
 * Events are suppressed in the test environment to keep test output clean.
 */
export function securityEvent(event: SecurityEventType, data: Record<string, unknown> = {}): void {
  if (env.NODE_ENV === 'test') return;

  const entry = {
    timestamp: new Date().toISOString(),
    event,
    ...data,
  };

  process.stdout.write(JSON.stringify(entry) + '\n');
}

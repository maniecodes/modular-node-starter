export const Actions = {
  CREATE: 'create',
  READ: 'read',
  UPDATE: 'update',
  DELETE: 'delete',
  ASSIGN: 'assign',
} as const;

export type Action = (typeof Actions)[keyof typeof Actions];

export const Resources = {
  USERS: 'users',
  ROLES: 'roles',
  PERMISSIONS: 'permissions',
} as const;

export type Resource = (typeof Resources)[keyof typeof Resources];

/**
 * Builds the canonical "resource.action" permission string used in authorize().
 * Example: permissionKey('users', 'read') → 'users.read'
 */
export function permissionKey(resource: Resource, action: Action): string {
  return `${resource}.${action}`;
}

export const DefaultRoles = {
  USER: 'user',
  ADMIN: 'admin',
} as const;

export type DefaultRole = (typeof DefaultRoles)[keyof typeof DefaultRoles];

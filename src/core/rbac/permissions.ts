// src/core/rbac/permissions.ts
export const Actions = {
  CREATE: 'create',
  READ: 'read',
  UPDATE: 'update',
  DELETE: 'delete',
} as const;

export type Action = (typeof Actions)[keyof typeof Actions];

export const Resources = {
  USERS: 'users',
  ROLES: 'roles',
  PERMISSIONS: 'permissions',
} as const;

export type Resource = (typeof Resources)[keyof typeof Resources];

/** Builds the canonical "action:resource" display string. */
export function permissionKey(action: Action, resource: Resource): string {
  return `${action}:${resource}`;
}

export const DefaultRoles = {
  SUPER_ADMIN: 'super_admin',
} as const;

export type DefaultRole = (typeof DefaultRoles)[keyof typeof DefaultRoles];

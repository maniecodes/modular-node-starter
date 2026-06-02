export const Permission = {
  USER_READ_OWN: 'user:read:own',
  USER_UPDATE_OWN: 'user:update:own',
  USER_DELETE_OWN: 'user:delete:own',
} as const;

export type Permission = (typeof Permission)[keyof typeof Permission];

export const Role = {
  USER: 'user',
  ADMIN: 'admin',
} as const;

export type Role = (typeof Role)[keyof typeof Role];

export const RolePermissions: Record<Role, Permission[]> = {
  [Role.USER]: [Permission.USER_READ_OWN, Permission.USER_UPDATE_OWN, Permission.USER_DELETE_OWN],
  [Role.ADMIN]: Object.values(Permission) as Permission[],
};

export function hasPermission(role: Role, permission: Permission): boolean {
  return RolePermissions[role]?.includes(permission) ?? false;
}

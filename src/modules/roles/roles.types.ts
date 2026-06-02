export interface CreateRoleInput {
  name: string;
  description?: string;
}

export interface CreatePermissionInput {
  action: string;
  resource: string;
  description?: string;
}

export interface AssignPermissionInput {
  permissionId: string;
}

export interface AssignRoleInput {
  userId: string;
}

export interface RoleResponse {
  id: string;
  name: string;
  description: string | null;
  createdAt: Date;
}

export interface PermissionResponse {
  id: string;
  action: string;
  resource: string;
  description: string | null;
  createdAt: Date;
}

export interface RoleWithPermissionsResponse extends RoleResponse {
  permissions: PermissionResponse[];
}

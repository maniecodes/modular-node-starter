/\*\*

- FILTER/SEARCH ENGINE — Integration Guide
-
- This document shows how to use the generic filter/search HOF(Higher-order function) on any resource endpoint.
- Pattern: config-based allowlist, per-endpoint declaration, reusable HOF.
  \*/

// ============================================================================
// EXAMPLE 1: Users with multiple filter types
// ============================================================================

import { withFilterSearch } from '@/common/helpers/filter-search.hof';
import { FilterSearchConfig } from '@/common/helpers/filter-search.types';

const usersFilterConfig: FilterSearchConfig = {
// Text search across name + email fields
searchableFields: ['firstName', 'lastName', 'email', 'phone'],

// Field-specific filters with type constraints
filterableFields: {
isActive: { type: 'boolean' },
role: { type: 'enum', enumValues: ['admin', 'user', 'moderator'] },
createdAt: { type: 'date', operators: ['range'] },
},
};

export const getUsersHandler = withFilterSearch(
(filters, pagination) => adminService.getUsers(filters, pagination),
usersFilterConfig,
'Retrieved users',
);

// Query usage:
// GET /admin/users?search=john&searchFields=firstName,email&page=1&limit=10
// GET /admin/users?filter=isActive:true&filter=role:admin
// GET /admin/users?filter=createdAt:2024-01-01,2024-12-31

// ============================================================================
// EXAMPLE 2: Roles (enum + text search only)
// ============================================================================

const rolesFilterConfig: FilterSearchConfig = {
searchableFields: ['name', 'description'],
filterableFields: {
// Only name filtering, no date range
status: { type: 'enum', enumValues: ['active', 'archived'] },
},
};

export const getRolesHandler = withFilterSearch(
(filters, pagination) => adminService.getRoles(filters, pagination),
rolesFilterConfig,
'Retrieved roles',
);

// ============================================================================
// EXAMPLE 3: Audit logs (timestamps + event filtering)
// ============================================================================

const auditLogsFilterConfig: FilterSearchConfig = {
searchableFields: ['action', 'description'],
filterableFields: {
eventType: { type: 'enum', enumValues: ['LOGIN', 'LOGOUT', 'UPDATE', 'DELETE'] },
severity: { type: 'enum', enumValues: ['info', 'warning', 'critical'] },
userId: { type: 'string' },
createdAt: { type: 'date', operators: ['range'] },
},
};

export const getAuditLogsHandler = withFilterSearch(
(filters, pagination) => auditService.getAuditLogs(filters, pagination),
auditLogsFilterConfig,
'Retrieved audit logs',
);

// ============================================================================
// EXAMPLE 4: Without Pagination (using withFilterSearchOnly)
// ============================================================================

import { withFilterSearchOnly } from '@/common/helpers/filter-search.hof';

const simpleSearchConfig: FilterSearchConfig = {
searchableFields: ['name'],
filterableFields: {
status: { type: 'enum', enumValues: ['active', 'inactive'] },
},
};

export const searchRolesHandler = withFilterSearchOnly(
(filters) => adminService.searchRoles(filters),
simpleSearchConfig,
'Search results',
);

// ============================================================================
// IMPLEMENTING THE SERVICE LAYER
// ============================================================================

export async function getAuditLogs(
filters: ParsedFilters,
pagination: ParsedPagination,
) {
// Build Prisma where clause from filters
const where: any = {};

if (filters.search) {
const { query, fields } = filters.search;
where.OR = fields.map((field) => ({
[field]: { contains: query, mode: 'insensitive' },
}));
}

if (filters.filters.eventType) {
where.eventType = filters.filters.eventType;
}

if (filters.filters.severity) {
where.severity = filters.filters.severity;
}

if (filters.filters.userId) {
where.userId = filters.filters.userId;
}

if (filters.filters.createdAt) {
const range = filters.filters.createdAt as { start: string; end: string };
where.createdAt = {
gte: new Date(range.start),
lte: new Date(range.end),
};
}

const [items, total] = await Promise.all([
prisma.auditLog.findMany({
where,
skip: pagination.skip,
take: pagination.take,
orderBy: { createdAt: 'desc' },
}),
prisma.auditLog.count({ where }),
]);

return { items, total };
}

// ============================================================================
// SECURITY CHECKLIST FOR NEW ENDPOINTS
// ============================================================================

/\*\*

- When adding filter/search to a new resource:
-
- 1.  Define FilterSearchConfig with ONLY the fields you want exposed
- - Do NOT include password, internal flags, sensitive data
- - Do NOT include unindexed columns (check your database indexes)
-
- 2.  List searchableFields for text search
- - Typically name, email, description, etc.
- - NOT numeric IDs, timestamps, or internal metadata
-
- 3.  List filterableFields with explicit type constraints
- - Boolean filters for true/false flags (isActive, isDeleted)
- - Enum filters for status fields (restrict to predefined values)
- - Date filters for timestamp ranges
- - Avoid arbitrary string filters unless search is better
-
- 4.  In the repository, validate each filter value
- - The parser already validates types, but you validate logic
- - Example: don't let a user filter by another user's records unless authorized
-
- 5.  Add indexes to searchable/filterable fields
- - Prisma migration: CREATE INDEX idx_user_email ON "User"(email);
- - Composite indexes for multi-field queries
    \*/

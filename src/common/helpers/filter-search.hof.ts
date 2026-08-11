import { Request, Response } from 'express';
import { parsePaginationQuery } from './pagination';
import { parseFilterSearch } from './filter-search.parser';
import { FilterSearchConfig, ParsedFilters } from './filter-search.types';
import { buildPaginatedResponse } from './pagination';
import { sendSuccess } from './response';

/**
 * Higher-order function combining pagination + filter/search.
 * Mirrors the `withPagination` pattern but adds filter/search support.
 *
 * Usage:
 *   export const getUsersHandler = withFilterSearch(
 *     (filters, pagination) => adminService.getUsers(filters, pagination),
 *     {
 *       searchableFields: ['name', 'email'],
 *       filterableFields: {
 *         isActive: { type: 'boolean' },
 *         role: { type: 'enum', enumValues: ['admin', 'user'] },
 *       },
 *     },
 *     'Retrieved users',
 *   );
 *
 * Query params:
 *   ?search=john&searchFields=name,email&filter=isActive:true&page=1&limit=10
 */
export function withFilterSearch<T>(
  handler: (filters: ParsedFilters, pagination: any) => Promise<{ items: T[]; total: number }>,
  config: FilterSearchConfig,
  successMessage: string,
) {
  return async (req: Request, res: Response): Promise<void> => {
    // Parse pagination (existing helper)
    const pagination = parsePaginationQuery(req.query as Record<string, unknown>);

    // Parse filters & search
    const filters = parseFilterSearch(req, config);

    // Call service
    const { items, total } = await handler(filters, pagination);

    // Build paginated response
    const response = buildPaginatedResponse(items, total, pagination, req);

    sendSuccess(res, response, successMessage);
  };
}

/**
 * Variant: filter-search WITHOUT pagination.
 * Use when you only want filtering/searching, no pagination.
 */
export function withFilterSearchOnly<T>(
  handler: (filters: ParsedFilters) => Promise<T[]>,
  config: FilterSearchConfig,
  successMessage: string,
) {
  return async (req: Request, res: Response): Promise<void> => {
    const filters = parseFilterSearch(req, config);
    const items = await handler(filters);
    sendSuccess(res, items, successMessage);
  };
}

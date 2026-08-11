import { Request } from 'express';
import { AppError } from '@/core/errors/AppError';
import { FilterSearchConfig, ParsedFilters, FieldType } from './filter-search.types';

/**
 * Parse and validate filter/search query parameters against a whitelist config.
 * 
 * Query format:
 *   ?search=john&searchFields=name,email
 *   ?filter=isActive:true&filter=role:admin&filter=createdAt:2024-01-01,2024-12-31
 * 
 * @param req Express request with query params
 * @param config Whitelist of allowed search/filter fields
 * @returns Validated filters ready for the service layer
 * @throws AppError if an invalid field or value is detected
 */
export function parseFilterSearch(req: Request, config: FilterSearchConfig): ParsedFilters {
  const query = req.query as Record<string, any>;
  const result: ParsedFilters = { filters: {} };

  // ============================================================================
  // Search: text query across whitelisted fields
  // ============================================================================
  const searchQuery = query.search as string | undefined;
  const searchFieldsParam = query.searchFields as string | undefined;

  if (searchQuery) {
    const allSearchable = config.searchableFields || Object.keys(config.filterableFields);
    const requestedFields = searchFieldsParam
      ? searchFieldsParam.split(',').map((f) => f.trim())
      : allSearchable;

    // Validate: all requested search fields must be in the whitelist
    const invalid = requestedFields.filter((f) => !allSearchable.includes(f));
    if (invalid.length > 0) {
      throw new AppError(`Search not allowed on fields: ${invalid.join(', ')}`, 400);
    }

    result.search = {
      query: searchQuery,
      fields: requestedFields,
    };
  }

  // ============================================================================
  // Filters: key:value pairs, with validation per field type
  // ============================================================================
  const filterParams = Array.isArray(query.filter)
    ? query.filter
    : query.filter
      ? [query.filter]
      : [];

  for (const filterParam of filterParams) {
    const [fieldName, ...valueParts] = (filterParam as string).split(':');
    const fieldValue = valueParts.join(':'); // in case value contains ':'

    if (!fieldName || !fieldValue) {
      throw new AppError('Invalid filter format. Use: filter=fieldName:value', 400);
    }

    // Validate: field must be in whitelist
    const fieldConfig = config.filterableFields[fieldName];
    if (!fieldConfig) {
      throw new AppError(`Filter not allowed on field: ${fieldName}`, 400);
    }

    // Coerce & validate value based on type
    const coercedValue = coerceFilterValue(fieldValue, fieldConfig);
    result.filters[fieldName] = coercedValue;
  }

  return result;
}

/**
 * Coerce a string filter value to its target type and validate.
 */
function coerceFilterValue(value: string, config: any): unknown {
    const { type, enumValues } = config;

    switch (type) {
        case 'string':
            return value; // no coercion

        case 'number':
            const num = Number(value);
            if (isNaN(num)) throw new AppError(`Invalid number: ${value}`, 400);
            return num;

        case 'boolean':
            if (value === 'true') return true;
            if (value === 'false') return false;
            throw new AppError(`Invalid boolean: ${value}. Use "true" or "false"`, 400);

        case 'date':
            // Support range values: "2024-01-01,2024-12-31"
            if (config.operators?.includes('range') && value.includes(',')) {
                const [start, end] = value.split(',').map((v: string) => v.trim());
                if (!start || !end) throw new AppError(`Invalid date range: ${value}`, 400);
                const startDate = new Date(start);
                const endDate = new Date(end);
                if (isNaN(startDate.getTime())) throw new AppError(`Invalid start date: ${start}`, 400);
                if (isNaN(endDate.getTime())) throw new AppError(`Invalid end date: ${end}`, 400);
                return { start: startDate, end: endDate };
            }
            const date = new Date(value);
            if (isNaN(date.getTime())) throw new AppError(`Invalid date: ${value}`, 400);
            return date;

        case 'enum':
            if (!enumValues?.includes(value)) {
                throw new AppError(
                    `Invalid enum value: ${value}. Allowed: ${enumValues.join(', ')}`,
                    400,
                );
            }
            return value;

        case 'range':
            // range values are comma-separated: "2024-01-01,2024-12-31"
            const [start, end] = value.split(',').map((v) => v.trim());
            if (!start || !end) throw new AppError('Range requires two values: start,end', 400);
            return { start, end };

        default:
            throw new AppError(`Unknown type: ${type}`, 500);
    }
}

/**
 * Helper: get default operators for a field type.
 */
export function getDefaultOperators(type: FieldType): string[] {
    switch (type) {
        case 'string':
            return ['eq', 'in']; // equality or IN list
        case 'number':
        case 'date':
            return ['eq', 'gt', 'gte', 'lt', 'lte', 'range'];
        case 'boolean':
        case 'enum':
            return ['eq'];
        default:
            return ['eq'];
    }
}

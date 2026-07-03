/**
 * Defines which fields are searchable and/or filterable on a resource.
 * Each endpoint supplies this config to restrict what can be queried.
 */

export type FieldType = 'string' | 'number' | 'boolean' | 'date' | 'enum';

export type FilterOperator = 'eq' | 'gt' | 'gte' | 'lt' | 'lte' | 'range' | 'in';

export type SearchType = 'contains';

export interface FieldConfig {
    type: FieldType;
    operators?: FilterOperator[]; // defaults based on type if omitted
    searchable?: boolean; // for text fields, allow partial match search
    enumValues?: string[]; // required if type === 'enum'
}

/**
 * Config object passed to the HOF.
 * Declares exactly which fields can be searched/filtered.
 */
export interface FilterSearchConfig {
    /**
     * Fields that support text-based search (substring matching).
     * Query param: ?search=foo&searchFields=name,email
     * (If not provided, search applies to all listed fields)
     */
    searchableFields?: string[];

    /**
     * Filterable fields and their constraints.
     * Query params: ?filter=isActive:true&filter=role:admin
     */
    filterableFields: Record<string, FieldConfig>;
}

/**
 * Parsed result after validating query params against the config.
 * Ready to pass to the service layer.
 */
export interface ParsedFilters {
    search?: {
        query: string;
        fields: string[];
    };
    filters: Record<string, unknown>; // field -> validated value
}

import { Request } from 'express';
import { PaginatedResult, PaginationLinks, PaginationMeta } from '@/common/types';

const DEFAULT_PAGE = 1;
const DEFAULT_PER_PAGE = 20;
const MAX_PER_PAGE = 100;

export interface ParsedPagination {
    page: number;
    perPage: number;
    skip: number;
    take: number;
}

export function parsePaginationQuery(query: Record<string, unknown>): ParsedPagination {
    const page = Math.max(1, parseInt(String(query.page ?? DEFAULT_PAGE), 10) || DEFAULT_PAGE);
    const perPage = Math.min(
        MAX_PER_PAGE,
        Math.max(1, parseInt(String(query.perPage ?? DEFAULT_PER_PAGE), 10) || DEFAULT_PER_PAGE),
    );
    return { page, perPage, skip: (page - 1) * perPage, take: perPage };
}

export function buildPaginatedResponse<T>(
    items: T[],
    total: number,
    pagination: ParsedPagination,
    req: Request,
): PaginatedResult<T> {
    const { page, perPage } = pagination;
    const totalPages = Math.max(1, Math.ceil(total / perPage));

    const baseUrl = `${req.protocol}://${req.get('host')}${req.path}`;
    const makeLink = (p: number) => `${baseUrl}?page=${p}&perPage=${perPage}`;

    const meta: PaginationMeta = {
        total,
        page,
        perPage,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
    };

    const links: PaginationLinks = {
        first: makeLink(1),
        last: makeLink(totalPages),
        prev: page > 1 ? makeLink(page - 1) : null,
        next: page < totalPages ? makeLink(page + 1) : null,
    };

    return { data: items, meta, links };
}

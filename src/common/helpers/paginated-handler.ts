// src/common/helpers/paginated-handler.ts
import { Response } from 'express';
import { AuthenticatedRequest } from '@/common/types';
import { AppError } from '@/core/errors/AppError';
import { parsePaginationQuery, buildPaginatedResponse, ParsedPagination } from './pagination';
import { sendPaginatedSuccess } from './response';

type PaginatedFetcher<T> = (req: AuthenticatedRequest, pagination: ParsedPagination) => Promise<{ items: T[]; total: number }>;

export function withPagination<T>(
    fetcher: PaginatedFetcher<T>,
    message: string,
) {
    return async (req: AuthenticatedRequest, res: Response): Promise<void> => {
        if (!req.user) throw new AppError('Unauthenticated', 401);

        const pagination = parsePaginationQuery(req.query as Record<string, unknown>);
        const { items, total } = await fetcher(req, pagination);
        const result = buildPaginatedResponse(items, total, pagination, req);
        sendPaginatedSuccess(res, result, message);
    };
}
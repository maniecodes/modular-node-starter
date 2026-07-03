import { Prisma } from '@prisma/client';
import { ParsedFilters } from '@/common/helpers/filter-search.types';
import { prisma } from '@/core/database/prisma';

/**
 * Example: Admin service using filter/search on the users endpoint.
 * Shows how to translate ParsedFilters into Prisma query logic.
 */

export async function getUsers(
    filters: ParsedFilters,
    pagination: { skip: number; take: number },
) {
    const where: Prisma.UserWhereInput = {};

    // ============================================================================
    // Apply search (text across multiple fields)
    // ============================================================================
    if (filters.search) {
        const { query, fields } = filters.search;

        // For Prisma: combine multiple field searches with OR
        // Example: search name OR email for substring match
        const searchConditions = fields.map((field) => ({
            [field]: { contains: query, mode: 'insensitive' as const },
        }));

        where.OR = searchConditions;
    }

    // ============================================================================
    // Apply explicit filters (field-specific constraints)
    // ============================================================================
    if (filters.filters.isActive !== undefined) {
        where.isActive = filters.filters.isActive as boolean;
    }

    if (filters.filters.role) {
        // If filtering by role, join the role through UserRole
        where.roles = {
            some: {
                role: {
                    name: filters.filters.role as string,
                },
            },
        };
    }

    if (filters.filters.createdAt) {
        const range = filters.filters.createdAt as { start: string; end: string };
        where.createdAt = {
            gte: new Date(range.start),
            lte: new Date(range.end),
        };
    }

    // ============================================================================
    // Query with pagination
    // ============================================================================
    const [items, total] = await Promise.all([
        prisma.user.findMany({
            where,
            skip: pagination.skip,
            take: pagination.take,
            select: {
                id: true,
                firstName: true,
                lastName: true,
                email: true,
                phone: true,
                isActive: true,
                createdAt: true,
                roles: {
                    select: {
                        role: {
                            select: { name: true },
                        },
                    },
                },
            },
        }),
        prisma.user.count({ where }),
    ]);

    return { items, total };
}

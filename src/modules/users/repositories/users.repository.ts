import { prisma } from '@/core/database/prisma';
import { UpdateUserInput } from '../users.types';
import { OtpPurpose, OtpType } from '@prisma/client';

export async function findById(id: string) {
  return prisma.user.findUnique({
    where: { id },
    select: { id: true, firstName: true, lastName: true, email: true, phone: true, createdAt: true },
  });
}

export async function updateById(id: string, data: UpdateUserInput) {
  return prisma.user.update({
    where: { id },
    data,
    select: { id: true, firstName: true, lastName: true, email: true, phone: true, createdAt: true },
  });
}

export async function deleteById(id: string): Promise<void> {
  await prisma.user.delete({ where: { id } });
}

export async function findUserByEmail(email: string) {
  if (!email) return null;

  return prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      phone: true,
      password: true,
      isActive: true,
      isVerified: true,
      isEmailVerified: true,
      isPhoneVerified: true,
    },
  });
}

export async function findUserByPhone(phone: string) {
  if (!phone) return null;

  return prisma.user.findUnique({
    where: { phone },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      phone: true,
      password: true,
      isActive: true,
      isVerified: true,
      isEmailVerified: true,
      isPhoneVerified: true,
    },
  });
}

export async function findUserById(id: string) {
  return prisma.user.findUnique({
    where: { id },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      phone: true,
      isActive: true,
      isEmailVerified: true,
      isPhoneVerified: true,
    },
  });
}

export async function createUser(data: {
  firstName: string;
  lastName: string;
  email?: string;
  phone?: string;
  password: string;
}) {
  return prisma.user.create({
    data,
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      phone: true,
      isVerified: true,
      isEmailVerified: true,
      isPhoneVerified: true,
    },
  });
}

export async function createUserWithRoles(
  data: {
    firstName: string;
    lastName: string;
    email?: string;
    phone?: string;
    password: string;
    isVerified?: boolean;
    isEmailVerified?: boolean;
    isPhoneVerified?: boolean;
  },
  roleIds: string[],
  assignedBy?: string,
) {
  return prisma.$transaction(async (tx) => {
    const user = await tx.user.create({
      data,
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        phone: true,
        isVerified: true,
        isEmailVerified: true,
        isPhoneVerified: true,
      },
    });

    await Promise.all(
      roleIds.map((roleId) =>
        tx.userRole.upsert({
          where: { userId_roleId: { userId: user.id, roleId } },
          update: {},
          create: {
            userId: user.id,
            roleId,
            assignedBy: assignedBy ?? user.id,
          },
        }),
      ),
    );

    return user;
  });
}

export async function markUserAsVerified(userId: string, method: OtpType): Promise<void> {
  const data =
    method === OtpType.EMAIL
      ? { isVerified: true, isEmailVerified: true }
      : { isVerified: true, isPhoneVerified: true };

  await prisma.user.update({
    where: { id: userId },
    data,
  });
}

export async function findRolesByNames(names: string[]) {
  return prisma.role.findMany({
    where: { name: { in: names } },
    select: {
      id: true,
      name: true,
      permissions: {
        select: {
          permission: {
            select: { action: true, resource: true },
          },
        },
      },
    },
  });
}

export async function assignRolesToUser(
  userId: string,
  roleIds: string[],
  assignedBy?: string,
): Promise<void> {
  await prisma.$transaction(
    roleIds.map((roleId) =>
      prisma.userRole.upsert({
        where: { userId_roleId: { userId, roleId } },
        update: {},
        create: { userId, roleId, assignedBy },
      }),
    ),
  );
}

export async function updateUserPassword(userId: string, hashedPassword: string): Promise<void> {
  await prisma.user.update({
    where: { id: userId },
    data: { password: hashedPassword },
  });
}

export async function findUserRoleNames(userId: string): Promise<string[]> {
  const userRoles = await prisma.userRole.findMany({
    where: { userId },
    select: {
      role: {
        select: { name: true },
      },
    },
  });

  return userRoles.map((ur) => ur.role.name);
}


/**
 *  Helper function to find all permission keys (in the format "resource.action") for a user based on their assigned roles. 
 *  This is used during authorization checks to determine if a user has the necessary permissions to perform an action.
 * @param userId // The ID of the user for whom to retrieve permission keys
 * @returns An array of permission keys that the user has through their roles
 */
export async function findUserPermissionKeys(userId: string): Promise<string[]> {
  const userRoles = await prisma.userRole.findMany({
    where: { userId },
    select: {
      role: {
        select: {
          permissions: {
            select: {
              permission: {
                select: { action: true, resource: true },
              },
            },
          },
        },
      },
    },
  });

  return [
    ...new Set(
      userRoles.flatMap((ur) =>
        ur.role.permissions.map((rp) => `${rp.permission.resource}.${rp.permission.action}`),
      ),
    ),
  ];
}

/**
 *  Helper function to create a new user based on an accepted invite, assign them the roles specified in the invite, and mark the invite as used. 
 *  This is used during the onboarding flow when a user accepts an invite and we need to create their account with the appropriate roles.
 * @param input The input parameters for creating the invited user, including personal details, password, role IDs, and optionally the ID of the user who assigned the roles.
 * @returns The newly created user with their assigned roles.
 */
export async function createInvitedUserWithRoles(input: {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  roleIds: string[];
  assignedBy?: string;
}) {
  return prisma.$transaction(async (tx) => {
    const user = await tx.user.create({
      data: {
        firstName: input.firstName,
        lastName: input.lastName,
        email: input.email,
        password: input.password,
        isVerified: true,
        isEmailVerified: true,
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        phone: true,
        isEmailVerified: true,
        isPhoneVerified: true,
      },
    });

    await Promise.all(
      input.roleIds.map((roleId) =>
        tx.userRole.create({
          data: {
            userId: user.id,
            roleId,
            assignedBy: input.assignedBy,
          },
        }),
      ),
    );

    return user;
  });
}
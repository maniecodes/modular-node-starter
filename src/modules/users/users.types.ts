// src/modules/users/users.types.ts
export interface UpdateUserInput {
  firstName?: string;
  lastName?: string;
}

export interface UserProfile {
  id: string;
  firstName: string;
  lastName: string;
  email: string | null;
  phone: string | null;
  createdAt: Date;
}

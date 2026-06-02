// src/modules/users/users.types.ts
export interface UpdateUserInput {
  name?: string;
}

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  createdAt: Date;
}

import type { User } from './db';

export interface PublicUser {
  id: number;
  name: string;
  email: string;
  role: string;
  created_at: string;
}

export function toPublicUser(user: User): PublicUser {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    created_at: user.created_at,
  };
}

export function toPublicUsers(users: User[]): PublicUser[] {
  return users.map(toPublicUser);
}

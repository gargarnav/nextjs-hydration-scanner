// Mirrors patent?/vulnerable-nextjs-poc/src/lib/db.ts exactly
export interface User {
  id: number;
  name: string;
  email: string;
  password_hash: string;
  two_factor_secret: string;
  api_key: string;
  ssn: string;
  role: string;
  created_at: string;
}

export interface SafeUser {
  id: number;
  name: string;
  email: string;
  role: string;
  created_at: string;
}

export async function getUsers(): Promise<User[]> {
  return [];
}

export async function getUserById(id: number): Promise<User | null> {
  return null;
}

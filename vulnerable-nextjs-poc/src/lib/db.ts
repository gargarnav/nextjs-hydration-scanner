import fs from 'fs';
import path from 'path';

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

export async function getUsers(): Promise<User[]> {
  const filePath = path.join(process.cwd(), 'src', 'db', 'users.json');
  try {
    const fileContents = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(fileContents);
  } catch (error) {
    console.error('Error reading generic users.json', error);
    return [];
  }
}

export async function getUserById(id: number): Promise<User | null> {
  const users = await getUsers();
  return users.find(u => u.id === id) || null;
}

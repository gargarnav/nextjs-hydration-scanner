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
  return [
    {
      id: 1,
      name: "Alice",
      email: "alice@example.com",
      password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/o6GxEOG5a",
      two_factor_secret: "JBSWY3DPEHPK3PXP",
      api_key: "sk_live_abc123def456ghij",
      ssn: "123-45-6789",
      role: "user",
      created_at: "2024-01-01T00:00:00Z",
    },
  ];
}

import { getUsers } from '@/lib/db';
import UserListClient from './UserListClient';

export default async function VulnerableAppRouterPage() {
  // Fetching all user data securely on the server
  const users = await getUsers();

  return (
    <main className="p-8 font-sans">
      <h1 className="text-3xl font-bold mb-4 text-red-600">
        Vulnerable App Router PoC
      </h1>
      <p className="mb-8 text-gray-700">
        This page demonstrates a Server Component fetching raw database objects and passing them 
        directly as props to a Client Component. Inspect the HTML source or React Developer Tools 
        to find the leaked `password_hash` and `api_key` in the RSC payload.
      </p>

      {/* 
        VULNERABILITY:
        Passing the entire `users` array, which contains sensitive fields. 
        Next.js will serialize this entire array and embed it in the HTML payload 
        so the Client Component can hydrate with it.
      */}
      <UserListClient users={users} />
    </main>
  );
}

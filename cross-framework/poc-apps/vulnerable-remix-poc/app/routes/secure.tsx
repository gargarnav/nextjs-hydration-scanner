import { json } from '@remix-run/node';
import { useLoaderData } from '@remix-run/react';
import type { LoaderFunctionArgs } from '@remix-run/node';
import { getUsers } from '~/lib/db';
import { toPublicUsers } from '~/lib/dto';

// SECURE: DTO applied before json() — sensitive fields never reach the client.
export async function loader({ request }: LoaderFunctionArgs) {
  const users = await getUsers();
  return json({ users: toPublicUsers(users) });
}

export default function Secure() {
  const { users } = useLoaderData<typeof loader>();
  return (
    <main>
      <h1>Users (Secure)</h1>
      <ul>
        {users.map((u) => <li key={u.id}>{u.name} — {u.email}</li>)}
      </ul>
    </main>
  );
}

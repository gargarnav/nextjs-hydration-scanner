import { json } from '@remix-run/node';
import { useLoaderData } from '@remix-run/react';
import type { LoaderFunctionArgs } from '@remix-run/node';
import { getUsers } from '~/lib/db';

// VULNERABLE: raw User[] returned via json() — password_hash, api_key, ssn
// all land in window.__remixContext.state.loaderData and are visible to any client.
export async function loader({ request }: LoaderFunctionArgs) {
  const users = await getUsers();
  return json({ users });
}

export default function Index() {
  const { users } = useLoaderData<typeof loader>();
  return (
    <main>
      <h1>Users (Vulnerable)</h1>
      <ul>
        {users.map((u) => <li key={u.id}>{u.name} — {u.email}</li>)}
      </ul>
    </main>
  );
}

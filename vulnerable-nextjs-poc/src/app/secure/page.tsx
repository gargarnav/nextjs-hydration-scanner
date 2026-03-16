import { getUsers } from '@/lib/db';
import { toPublicUsers } from '@/lib/dto';
import SecureUserListClient from './SecureUserListClient';

export default async function SecureAppRouterPage() {
  const users = await getUsers();

  // MITIGATION:
  // Apply the DTO transform server-side, before the data is handed to
  // any Client Component.  The RSC serialization boundary only ever sees
  // PublicUser objects — sensitive fields are stripped before they can
  // enter the self.__next_f.push(...) payload.
  const publicUsers = toPublicUsers(users);

  return (
    <main className="p-8 font-sans">
      <h1 className="text-3xl font-bold mb-4 text-green-600">
        Secure App Router — DTO Mitigation
      </h1>
      <p className="mb-8 text-gray-700">
        This Server Component applies <code>toPublicUsers()</code> before passing data to
        the Client Component. Inspect the RSC payload in the HTML source — you will find{' '}
        <strong>no</strong> <code>password_hash</code>, <code>api_key</code>,{' '}
        <code>ssn</code>, or <code>two_factor_secret</code>.
      </p>

      <SecureUserListClient users={publicUsers} />
    </main>
  );
}

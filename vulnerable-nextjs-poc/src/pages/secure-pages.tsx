import React from 'react';
import { GetServerSideProps } from 'next';
import { getUsers } from '../lib/db';
import { toPublicUsers, PublicUser } from '../lib/dto';

interface Props {
  users: PublicUser[];
}

export default function SecurePagesRouter({ users }: Props) {
  const scriptTag = '<script id="__NEXT_DATA__" type="application/json">';

  return (
    <main className="p-8 font-sans">
      <h1 className="text-3xl font-bold mb-4 text-green-600">
        Secure Pages Router — DTO Mitigation
      </h1>
      <p className="mb-8 text-gray-700">
        This page uses the same <code>getServerSideProps</code> pattern but passes only a{' '}
        <code>PublicUser</code> DTO to the client. Inspect the{' '}
        <code>{scriptTag}</code> tag — you will find <strong>no</strong>{' '}
        <code>password_hash</code>, <code>api_key</code>, <code>ssn</code>, or{' '}
        <code>two_factor_secret</code>.
      </p>

      <div className="bg-white shadow p-6 rounded-lg border border-green-200">
        <h2 className="text-xl font-semibold mb-4">User Directory</h2>
        <ul className="space-y-4">
          {users.map((user) => (
            <li key={user.id} className="border-b pb-4 last:border-b-0">
              <p className="font-medium text-lg text-black">{user.name}</p>
              <p className="text-sm text-gray-500">{user.email}</p>
              <p className="text-xs text-blue-600 mt-1">Role: {user.role}</p>
            </li>
          ))}
        </ul>
      </div>
    </main>
  );
}

// MITIGATION:
// toPublicUsers() applies the DTO allowlist before the data is returned as props.
// Next.js serializes only the PublicUser shape into __NEXT_DATA__ —
// sensitive fields never enter the serialization pipeline.
export const getServerSideProps: GetServerSideProps<Props> = async () => {
  const users = await getUsers();

  return {
    props: {
      users: toPublicUsers(users),
    },
  };
};

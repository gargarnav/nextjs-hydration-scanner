import React from 'react';
import { GetServerSideProps } from 'next';
import { getUsers, User } from '../lib/db';

interface Props {
  users: User[];
}

export default function VulnerablePagesRouter({ users }: Props) {
  const scriptTag = '<script id="__NEXT_DATA__" type="application/json">';

  return (
    <main className="p-8 font-sans">
      <h1 className="text-3xl font-bold mb-4 text-red-600">
        Vulnerable Pages Router PoC
      </h1>
      <p className="mb-8 text-gray-700">
        This page demonstrates a classic Next.js (Pages Router) vulnerability. 
        <code>getServerSideProps</code> fetches raw database objects and returns them as props. 
        Inspect the HTML source for the <code>{scriptTag}</code> 
        tag at the bottom of the page to find the leaked <code>password_hash</code> and <code>api_key</code>.
      </p>

      <div className="bg-white shadow p-6 rounded-lg border border-red-200">
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

// VULNERABILITY: 
// Returning the raw database objects directly as props.
// Next.js serializes this into the HTML for client-side hydration.
export const getServerSideProps: GetServerSideProps<Props> = async () => {
  const users = await getUsers();
  
  return {
    props: {
      users,
    },
  };
};

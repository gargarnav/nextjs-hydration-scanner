'use client';

import { User } from '@/lib/db';
import { useState } from 'react';

interface UserListClientProps {
  users: User[];
}

export default function UserListClient({ users }: UserListClientProps) {
  const [expandedId, setExpandedId] = useState<number | null>(null);

  return (
    <div className="bg-white shadow p-6 rounded-lg border border-red-200">
      <h2 className="text-xl font-semibold mb-4">User Directory</h2>
      <ul className="space-y-4">
        {users.map((user) => (
          <li key={user.id} className="border-b pb-4 last:border-b-0">
            <div className="flex justify-between items-center">
              <div>
                <p className="font-medium text-lg text-black">{user.name}</p>
                <p className="text-sm text-gray-500">{user.email}</p>
              </div>
              <button
                onClick={() => setExpandedId(expandedId === user.id ? null : user.id)}
                className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 transition"
              >
                {expandedId === user.id ? 'Hide Details' : 'View Details'}
              </button>
            </div>
            
            {/* The client only *displays* public information, but the *entire* user object was sent over the network! */}
            {expandedId === user.id && (
              <div className="mt-4 p-4 bg-gray-50 rounded text-sm text-gray-800">
                <p><strong>Role:</strong> {user.role}</p>
                <p><strong>Member Since:</strong> {new Date(user.created_at).toLocaleDateString()}</p>
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

'use client';

import { PublicUser } from '@/lib/dto';
import { useState } from 'react';

interface SecureUserListClientProps {
  users: PublicUser[];
}

export default function SecureUserListClient({ users }: SecureUserListClientProps) {
  const [expandedId, setExpandedId] = useState<number | null>(null);

  return (
    <div className="bg-white shadow p-6 rounded-lg border border-green-200">
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
                className="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600 transition"
              >
                {expandedId === user.id ? 'Hide Details' : 'View Details'}
              </button>
            </div>

            {expandedId === user.id && (
              <div className="mt-4 p-4 bg-gray-50 rounded text-sm text-gray-800">
                <p><strong>Role:</strong> {user.role}</p>
                <p><strong>Member Since:</strong> {new Date(user.created_at).toLocaleDateString()}</p>
                {/* TypeScript enforces the DTO shape — user.password_hash doesn't exist on PublicUser,
                    so even accidentally referencing it here would be a compile error. */}
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

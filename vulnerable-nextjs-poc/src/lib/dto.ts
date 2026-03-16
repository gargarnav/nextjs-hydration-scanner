/**
 * Data Transfer Objects (DTOs)
 * ============================
 * This module defines the *public-safe* shape of data that is allowed to
 * cross the server→client boundary.  It acts as an explicit allowlist:
 * only fields declared here can ever reach the client.
 *
 * The core principle is an ALLOWLIST, not a blocklist.
 * A blocklist (e.g. `delete user.password_hash`) is fragile — a new
 * sensitive column added to the DB will silently leak until someone
 * remembers to add it to the blocklist.  An allowlist fails closed:
 * new fields are invisible to the client until explicitly whitelisted.
 */

import type { User } from './db';

/**
 * PublicUser — the only shape ever sent to the browser.
 * Contains no credentials, secrets, or PII beyond email.
 */
export interface PublicUser {
  id: number;
  name: string;
  email: string;
  role: string;
  created_at: string;
}

/**
 * Strip a full User record down to its public-safe DTO.
 * Uses explicit destructuring so TypeScript enforces the shape at compile time.
 * Any field not listed here is structurally excluded.
 */
export function toPublicUser(user: User): PublicUser {
  return {
    id:         user.id,
    name:       user.name,
    email:      user.email,
    role:       user.role,
    created_at: user.created_at,
  };
}

export function toPublicUsers(users: User[]): PublicUser[] {
  return users.map(toPublicUser);
}

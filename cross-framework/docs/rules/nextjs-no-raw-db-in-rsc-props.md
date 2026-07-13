# nextjs/no-raw-db-in-rsc-props

Disallow passing props with sensitive database fields through JSX attributes (App Router / RSC).

## Why this rule exists

In the App Router, data fetched in a Server Component can be passed as props to Client Components.
Those props are serialized into React's RSC streaming payload (`self.__next_f.push([...])`) embedded
in the HTML, making them readable by any HTTP client.

While React's `taintObjectReference` API can catch this at runtime, it:
- Is experimental and opt-in per-value
- Doesn't protect cloned objects
- Requires manual wrapping of every sensitive object
- Fails silently on non-tainted copies

This rule catches the issue statically at write-time, with no per-object opt-in burden.

## Examples

### Incorrect

```tsx
// app/users/page.tsx (Server Component)
import { getUsers } from '@/lib/db';
import { UserList } from './UserList'; // 'use client'

export default async function UsersPage() {
  const users = await getUsers();
  return <UserList users={users} />; // ← User[] has password_hash in RSC payload
}
```

### Correct

```tsx
import { getUsers } from '@/lib/db';
import { toPublicUsers } from '@/lib/dto';
import { UserList } from './UserList';

export default async function UsersPage() {
  const users = await getUsers();
  return <UserList users={toPublicUsers(users)} />; // PublicUser[]: safe
}
```

## Known limitations (v0.1)

This v0.1 rule uses a broad heuristic: it flags any JSX attribute expression whose TypeScript type
contains a sensitive field. This can produce **false positives** when passing data between two
Server Components (since Server→Server props are NOT serialized into the payload).

In v0.2, cross-file `'use client'` detection will be added to eliminate false positives.

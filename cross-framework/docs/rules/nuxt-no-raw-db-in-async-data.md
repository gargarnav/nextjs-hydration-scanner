# nuxt/no-raw-db-in-async-data

Disallow returning raw database types with sensitive fields from Nuxt server API handlers.

## Why this rule exists

Nuxt serializes data returned from `server/api/` and `server/routes/` handlers into
`__NUXT_DATA__` / `window.__NUXT__` embedded in the page HTML. Any HTTP client can read this.

## Examples

### Incorrect

```ts
// server/api/users.ts
import { getUsers } from '../db';

export default defineEventHandler(async (event) => {
  const users = await getUsers();
  return users; // ← User[] has ssn, password_hash in __NUXT_DATA__
});
```

### Correct

```ts
import { getUsers } from '../db';
import { toPublicUsers } from '../dto';

export default defineEventHandler(async (event) => {
  const users = await getUsers();
  return toPublicUsers(users); // PublicUser[]: safe
});
```

## When it fires

The rule is **only active in files matching** `server/api/` or `server/routes/` path segments.
`.vue` SFC `useAsyncData()` support is planned for v0.2.

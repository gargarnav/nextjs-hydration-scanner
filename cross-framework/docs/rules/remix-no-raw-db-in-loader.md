# remix/no-raw-db-in-loader

Disallow returning raw database types with sensitive fields from Remix `loader()` functions.

## Why this rule exists

Remix serializes the return value of `loader()` into `window.__remixContext` embedded in the HTML.
Handles `json({ ... })`, `Response.json({ ... })`, and bare return objects.

## Examples

### Incorrect

```ts
// app/routes/_index.tsx
import { json } from '@remix-run/node';
import { getUsers } from '~/db.server';

export async function loader() {
  const users = await getUsers();
  return json({ users }); // ← User[] has api_key in window.__remixContext
}
```

### Correct

```ts
import { json } from '@remix-run/node';
import { getUsers } from '~/db.server';
import { toPublicUsers } from '~/dto.server';

export async function loader() {
  const users = await getUsers();
  return json({ users: toPublicUsers(users) }); // PublicUser[]: safe
}
```

## When it fires

Fires on exported `loader` functions (declaration or `export const loader = ...`) when:
- `return json({ <value> })` - checks the argument to `json()`
- `return Response.json({ <value> })` - same
- `return { <value> }` - bare object return

The rule checks whether any property value's TypeScript type contains a sensitive field.

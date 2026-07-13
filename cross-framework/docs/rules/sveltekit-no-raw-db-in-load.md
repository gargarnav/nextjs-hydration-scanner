# sveltekit/no-raw-db-in-load

Disallow returning raw database types with sensitive fields from SvelteKit `load()` functions.

## Why this rule exists

SvelteKit serializes the return value of `load()` in `+page.server.ts` / `+layout.server.ts` into
a `__sveltekit_data` JSON blob embedded in the page HTML. Any HTTP client can read this without
authentication.

## Examples

### Incorrect

```ts
// src/routes/+page.server.ts
import { getUsers } from '$lib/db';

export async function load() {
  const users = await getUsers();
  return { users }; // ← User[] has password_hash serialized into __sveltekit_data
}
```

### Correct

```ts
import { getUsers } from '$lib/db';
import { toPublicUsers } from '$lib/dto';

export async function load() {
  const users = await getUsers();
  return { users: toPublicUsers(users) }; // PublicUser[]: safe
}
```

## When it fires

The rule is **only active in files matching** `+page.server.ts` or `+layout.server.ts`
(and `.js` / `.mts` / `.cts` variants). It does not fire in regular `+page.ts` files.

It fires when an exported `load` function (arrow or declaration) returns an object where
one of the property values has a TypeScript type containing a sensitive field name.

## Configuration

```js
{
  plugins: { 'ssr-boundary': ssrBoundary },
  rules: {
    'ssr-boundary/sveltekit/no-raw-db-in-load': ['error', {
      sensitiveFields: ['internal_note'],
    }],
  },
}
```

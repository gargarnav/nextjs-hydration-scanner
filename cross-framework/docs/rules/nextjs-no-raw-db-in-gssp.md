# nextjs/no-raw-db-in-gssp

Disallow returning raw database types with sensitive fields from `getServerSideProps` or `getStaticProps`.

## Why this rule exists

When `getServerSideProps` returns an object with a `props` key, Next.js serializes those props into
`<script id="__NEXT_DATA__" type="application/json">` embedded in the HTML. **Every HTTP client can
read this tag without authentication.**

If the props contain a database object with sensitive fields (`password_hash`, `api_key`, `ssn`, etc.),
those values are exposed in plain text to every visitor, including unauthenticated crawlers.

The Pages Router has **zero runtime protection**. React's `taintObjectReference` API only covers
the App Router (RSC). This rule fills that gap statically at write-time.

## Examples

### Incorrect

```ts
// vulnerable-pages.tsx
import { getUsers } from '../lib/db';

export const getServerSideProps = async () => {
  const users = await getUsers();
  return {
    props: { users }, // ← User[] has password_hash, api_key, ssn ...
  };
};
```

The `User` type contains `password_hash` (CRITICAL). Next.js will serialize `users` into
`__NEXT_DATA__`, exposing every field to the browser.

### Correct

```ts
import { getUsers } from '../lib/db';
import { toPublicUsers } from '../lib/dto';

export const getServerSideProps = async () => {
  const users = await getUsers();
  return {
    props: { users: toPublicUsers(users) }, // PublicUser[]: no sensitive fields
  };
};
```

## When it fires

The rule fires when:
1. A function named `getServerSideProps` or `getStaticProps` is **exported** from the file.
2. The function returns `{ props: { ... } }`.
3. A value in the `props` object has a TypeScript type that contains a sensitive field name.

## Configuration

```js
// eslint.config.mjs
export default [
  {
    plugins: { 'ssr-boundary': ssrBoundary },
    rules: {
      'ssr-boundary/nextjs/no-raw-db-in-gssp': ['error', {
        sensitiveFields: ['internal_id', 'stripe_customer_id'], // extra fields
      }],
    },
  },
];
```

### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `sensitiveFields` | `string[]` | `[]` | Additional field names to flag beyond the built-in list. |

## Built-in sensitive field list

The full list is in [`sensitive-patterns.json`](../../sensitive-patterns.json) at the monorepo root.
Key patterns include: `password_hash`, `hashed_password`, `api_key`, `secret_key`, `access_token`,
`refresh_token`, `two_factor_secret`, `ssn`, `credit_card`, `cvv`, `private_key`, and more.

## Requirements

This rule requires **type-aware linting**. Add to your ESLint config:

```js
languageOptions: {
  parserOptions: {
    projectService: true,
    tsconfigRootDir: import.meta.dirname,
  },
},
```

## Known limitations

- Reports on the first sensitive field found per prop value (not all of them).
- Does not follow property spreads (e.g., `return { props: { ...user } }`).
- `any`-typed values are skipped (no false positives on untyped code).

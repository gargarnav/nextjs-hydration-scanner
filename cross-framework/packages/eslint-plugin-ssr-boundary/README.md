# eslint-plugin-ssr-boundary

ESLint rules that catch sensitive database fields crossing the server-client boundary at write-time, before they ship to production.

Supports **Next.js** (Pages Router + App Router), **SvelteKit**, **Remix**, and **Nuxt 3/4**.

## The vulnerability

SSR frameworks serialize server-fetched data into the HTML response for client-side hydration. If a raw database object is passed as props, its sensitive fields (`password_hash`, `api_key`, `ssn`, etc.) appear in plain text inside a `<script>` tag readable by any HTTP client, no authentication required.

```html
<!-- Anyone can curl this -->
<script id="__NEXT_DATA__" type="application/json">
{"props":{"pageProps":{"users":[{"id":1,"email":"alice@example.com",
  "password_hash":"$2b$12$abc...","api_key":"sk-live-XXXX","ssn":"123-45-6789"}]}}}
</script>
```

## Why not just use React's taint API?

React's `experimental_taintObjectReference` only covers the **App Router** (RSC), is **experimental**, requires **manually tainting every sensitive object**, and **silently fails on object clones**. It also does nothing for the Pages Router.

`eslint-plugin-ssr-boundary` enforces the DTO boundary statically at write-time across both routing paradigms and four frameworks, with no per-object opt-in burden.

## Installation

```bash
npm install --save-dev eslint-plugin-ssr-boundary @typescript-eslint/parser
```

> **Requires type-aware linting**: `parserOptions.projectService: true` must be set.

## Quick start

```js
// eslint.config.mjs
import tsParser from '@typescript-eslint/parser';
import ssrBoundary from 'eslint-plugin-ssr-boundary';

export default [
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    ...ssrBoundary.configs['recommended-nextjs'],
  },
];
```

For SvelteKit, Remix, or Nuxt replace `recommended-nextjs` with the appropriate preset:

| Preset | Rules enabled |
|---|---|
| `recommended-nextjs` | `nextjs/no-raw-db-in-gssp`, `nextjs/no-raw-db-in-rsc-props` |
| `recommended-sveltekit` | `sveltekit/no-raw-db-in-load` |
| `recommended-remix` | `remix/no-raw-db-in-loader` |
| `recommended-nuxt` | `nuxt/no-raw-db-in-async-data` |
| `recommended` | All 5 rules |

## Rules

| Rule | Description | Severity |
|---|---|---|
| [`nextjs/no-raw-db-in-gssp`](../../docs/rules/nextjs-no-raw-db-in-gssp.md) | Pages Router `getServerSideProps` / `getStaticProps` | error |
| [`nextjs/no-raw-db-in-rsc-props`](../../docs/rules/nextjs-no-raw-db-in-rsc-props.md) | App Router RSC→Client prop passing | error |
| [`sveltekit/no-raw-db-in-load`](../../docs/rules/sveltekit-no-raw-db-in-load.md) | `+page.server.ts` / `+layout.server.ts` load() | error |
| [`remix/no-raw-db-in-loader`](../../docs/rules/remix-no-raw-db-in-loader.md) | Route `loader()` (json() and bare return) | error |
| [`nuxt/no-raw-db-in-async-data`](../../docs/rules/nuxt-no-raw-db-in-async-data.md) | `server/api/` and `server/routes/` handlers | error |

## TypeScript requirement

This plugin uses TypeScript's type system to detect the types of values passed across the boundary. It requires:

1. `@typescript-eslint/parser` as the parser
2. `parserOptions.projectService: true` (or `project: true`) to enable type information
3. TypeScript ≥ 4.8

Without type information, the plugin cannot inspect what type a variable has and will throw an error.

## Sensitive fields detected

The plugin checks for field names matching patterns from [`sensitive-patterns.json`](../../sensitive-patterns.json):

**CRITICAL**: `password_hash`, `hashed_password`, `password`, `two_factor_secret`, `totp_secret`, `ssn`, `social_security_number`

**HIGH**: `api_key`, `apiKey`, `secret_key`, `secretKey`, `access_token`, `accessToken`, `refresh_token`, `refreshToken`, `private_key`, `privateKey`, `auth_token`, `authToken`, `session_token`, `sessionToken`

**MEDIUM**: `credit_card`, `card_number`, `cvv`, `date_of_birth`, `bank_account`

## Custom sensitive fields

```js
rules: {
  'ssr-boundary/nextjs/no-raw-db-in-gssp': ['error', {
    sensitiveFields: ['internal_id', 'stripe_customer_id'],
  }],
}
```

## Related work

This plugin is part of the `ssr-boundary` security suite alongside `ssr-boundary-scanner`, a black-box deployed-URL scanner that detects leaked fields in live hydration payloads. See the [monorepo README](../../README.md) for the full picture.

## License

MIT

import { RuleTester } from '@typescript-eslint/rule-tester';
import { afterAll, describe, it } from 'vitest';
import path from 'node:path';
import { noRawDbInLoader } from '../../../src/rules/remix/no-raw-db-in-loader.js';

RuleTester.afterAll = afterAll;
RuleTester.describe = describe;
RuleTester.it = it;

const FIXTURES = path.resolve(__dirname, '../../../fixtures/remix');

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: {
      projectService: {
        allowDefaultProject: ['*.ts', '*.tsx'],
        defaultProject: 'tsconfig.json',
      },
      tsconfigRootDir: FIXTURES,
    },
  },
});

ruleTester.run('no-raw-db-in-loader', noRawDbInLoader, {
  valid: [
    // DTO transform applied with json()
    {
      filename: path.join(FIXTURES, 'secure-route.ts'),
      code: `
        import { getUsers } from './db';
        import { toPublicUsers } from './dto';
        declare function json<T>(data: T): Response;
        export async function loader() {
          const users = await getUsers();
          return json({ users: toPublicUsers(users) });
        }
      `,
    },
    // Primitive values only
    {
      filename: path.join(FIXTURES, 'primitive-route.ts'),
      code: `
        declare function json<T>(data: T): Response;
        export async function loader() {
          return json({ title: 'Hello', count: 42 });
        }
      `,
    },
    // Non-exported loader — rule must not fire
    {
      filename: path.join(FIXTURES, 'non-exported.ts'),
      code: `
        import { getUsers } from './db';
        declare function json<T>(data: T): Response;
        async function loader() {
          const users = await getUsers();
          return json({ users });
        }
      `,
    },
  ],

  invalid: [
    // Raw User[] inside json()
    {
      filename: path.join(FIXTURES, 'vulnerable-route.ts'),
      code: `
        import { getUsers } from './db';
        declare function json<T>(data: T): Response;
        export async function loader() {
          const users = await getUsers();
          return json({ users });
        }
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
    // export const loader = ...
    {
      filename: path.join(FIXTURES, 'vulnerable-arrow.ts'),
      code: `
        import { getUsers } from './db';
        declare function json<T>(data: T): Response;
        export const loader = async () => {
          const users = await getUsers();
          return json({ users });
        };
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
    // Response.json() form
    {
      filename: path.join(FIXTURES, 'vulnerable-response-json.ts'),
      code: `
        import { getUsers } from './db';
        export async function loader() {
          const users = await getUsers();
          return Response.json({ users });
        }
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
    // Single user
    {
      filename: path.join(FIXTURES, 'vulnerable-single.ts'),
      code: `
        import { getUserById } from './db';
        declare function json<T>(data: T): Response;
        export async function loader() {
          const user = await getUserById(1);
          return json({ user });
        }
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
  ],
});

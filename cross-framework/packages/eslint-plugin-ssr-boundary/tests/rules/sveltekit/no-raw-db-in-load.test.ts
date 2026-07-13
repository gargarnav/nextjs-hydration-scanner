import { RuleTester } from '@typescript-eslint/rule-tester';
import { afterAll, describe, it } from 'vitest';
import path from 'node:path';
import { noRawDbInLoad } from '../../../src/rules/sveltekit/no-raw-db-in-load.js';

RuleTester.afterAll = afterAll;
RuleTester.describe = describe;
RuleTester.it = it;

const FIXTURES = path.resolve(__dirname, '../../../fixtures/sveltekit');
// SvelteKit rule only activates in +page.server.ts / +layout.server.ts files
const SERVER_FILE = path.join(FIXTURES, '+page.server.ts');
const NON_SERVER_FILE = path.join(FIXTURES, 'page.ts');

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

ruleTester.run('no-raw-db-in-load', noRawDbInLoad, {
  valid: [
    // DTO transform applied
    {
      filename: SERVER_FILE,
      code: `
        import { getUsers } from './db';
        import { toPublicUsers } from './dto';
        export async function load() {
          const users = await getUsers();
          return { users: toPublicUsers(users) };
        }
      `,
    },
    // Non-server file — rule must not activate
    {
      filename: NON_SERVER_FILE,
      code: `
        import { getUsers } from './db';
        export async function load() {
          const users = await getUsers();
          return { users };
        }
      `,
    },
    // Primitive return values — no sensitive fields
    {
      filename: SERVER_FILE,
      code: `
        export async function load() {
          return { title: 'Hello', count: 42 };
        }
      `,
    },
    // Non-exported load — rule must not fire
    {
      filename: SERVER_FILE,
      code: `
        import { getUsers } from './db';
        async function load() {
          const users = await getUsers();
          return { users };
        }
      `,
    },
  ],

  invalid: [
    // Raw User[] leaked from load()
    {
      filename: SERVER_FILE,
      code: `
        import { getUsers } from './db';
        export async function load() {
          const users = await getUsers();
          return { users };
        }
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
    // export const load = ...
    {
      filename: SERVER_FILE,
      code: `
        import { getUsers } from './db';
        export const load = async () => {
          const users = await getUsers();
          return { users };
        };
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
    // layout.server.ts file also activates the rule
    {
      filename: path.join(FIXTURES, '+layout.server.ts'),
      code: `
        import { getUsers } from './db';
        export async function load() {
          const users = await getUsers();
          return { users };
        }
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
    // Single user
    {
      filename: SERVER_FILE,
      code: `
        import { getUserById } from './db';
        export async function load() {
          const user = await getUserById(1);
          return { user };
        }
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
  ],
});

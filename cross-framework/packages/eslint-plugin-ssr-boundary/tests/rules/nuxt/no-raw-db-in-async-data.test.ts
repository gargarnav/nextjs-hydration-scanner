import { RuleTester } from '@typescript-eslint/rule-tester';
import { afterAll, describe, it } from 'vitest';
import path from 'node:path';
import { noRawDbInAsyncData } from '../../../src/rules/nuxt/no-raw-db-in-async-data.js';

RuleTester.afterAll = afterAll;
RuleTester.describe = describe;
RuleTester.it = it;

const FIXTURES = path.resolve(__dirname, '../../../fixtures/nuxt');
// Nuxt rule only activates in server/api/ or server/routes/ files
const SERVER_API_FILE = path.join(FIXTURES, 'server/api/users.ts');
const NON_SERVER_FILE = path.join(FIXTURES, 'pages/index.ts');

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: {
      projectService: {
        allowDefaultProject: [
          '*.ts',
          'server/*.ts',
          'server/api/*.ts',
          'server/routes/*.ts',
          'pages/*.ts',
        ],
        defaultProject: 'tsconfig.json',
      },
      tsconfigRootDir: FIXTURES,
    },
  },
});

ruleTester.run('no-raw-db-in-async-data', noRawDbInAsyncData, {
  valid: [
    // DTO transform applied
    {
      filename: SERVER_API_FILE,
      code: `
        import { getUsers } from '../../db';
        import { toPublicUsers } from '../../dto';
        declare function defineEventHandler(fn: Function): unknown;
        export default defineEventHandler(async (event: unknown) => {
          const users = await getUsers();
          return toPublicUsers(users);
        });
      `,
    },
    // Non-server file — rule must not activate
    {
      filename: NON_SERVER_FILE,
      code: `
        import { getUsers } from '../db';
        declare function defineEventHandler(fn: Function): unknown;
        export default defineEventHandler(async (event: unknown) => {
          const users = await getUsers();
          return users;
        });
      `,
    },
    // Primitive return values
    {
      filename: SERVER_API_FILE,
      code: `
        declare function defineEventHandler(fn: Function): unknown;
        export default defineEventHandler(async () => {
          return { message: 'OK', count: 42 };
        });
      `,
    },
  ],

  invalid: [
    // Raw User[] from defineEventHandler
    {
      filename: SERVER_API_FILE,
      code: `
        import { getUsers } from '../../db';
        declare function defineEventHandler(fn: Function): unknown;
        export default defineEventHandler(async (event: unknown) => {
          const users = await getUsers();
          return users;
        });
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
    // server/routes/ path also activates
    {
      filename: path.join(FIXTURES, 'server/routes/users.ts'),
      code: `
        import { getUsers } from '../../db';
        declare function defineEventHandler(fn: Function): unknown;
        export default defineEventHandler(async (event: unknown) => {
          const users = await getUsers();
          return users;
        });
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
    // Single user
    {
      filename: SERVER_API_FILE,
      code: `
        import { getUserById } from '../../db';
        declare function defineEventHandler(fn: Function): unknown;
        export default defineEventHandler(async (event: unknown) => {
          const user = await getUserById(1);
          return user;
        });
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
  ],
});

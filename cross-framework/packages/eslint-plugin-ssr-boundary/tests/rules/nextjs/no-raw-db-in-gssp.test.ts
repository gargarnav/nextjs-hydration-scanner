import { RuleTester } from '@typescript-eslint/rule-tester';
import { afterAll, describe, it } from 'vitest';
import path from 'node:path';
import { noRawDbInGssp } from '../../../src/rules/nextjs/no-raw-db-in-gssp.js';

RuleTester.afterAll = afterAll;
RuleTester.describe = describe;
RuleTester.it = it;

const FIXTURES = path.resolve(__dirname, '../../../fixtures/nextjs');

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: {
      projectService: {
        allowDefaultProject: ['*.tsx', '*.ts'],
        defaultProject: 'tsconfig.json',
      },
      tsconfigRootDir: FIXTURES,
    },
  },
});

ruleTester.run('no-raw-db-in-gssp', noRawDbInGssp, {
  valid: [
    // DTO transform applied — should not fire
    {
      filename: path.join(FIXTURES, 'secure-pages.tsx'),
      code: `
        import { getUsers } from './db';
        import { toPublicUsers, PublicUser } from './dto';

        type Props = { users: PublicUser[] };

        export const getServerSideProps = async (): Promise<{ props: Props }> => {
          const users = await getUsers();
          return { props: { users: toPublicUsers(users) } };
        };
      `,
    },
    // Primitive props — no sensitive fields
    {
      filename: path.join(FIXTURES, 'primitive-pages.tsx'),
      code: `
        export const getServerSideProps = async () => {
          return { props: { title: 'Hello', count: 42, enabled: true } };
        };
      `,
    },
    // Not exported — rule must not fire
    {
      filename: path.join(FIXTURES, 'non-exported.tsx'),
      code: `
        import { getUsers } from './db';
        async function getServerSideProps() {
          const users = await getUsers();
          return { props: { users } };
        }
      `,
    },
    // Different function name — not GSSP
    {
      filename: path.join(FIXTURES, 'other-fn.tsx'),
      code: `
        import { getUsers } from './db';
        export async function fetchUsers() {
          const users = await getUsers();
          return { props: { users } };
        }
      `,
    },
  ],

  invalid: [
    // Raw User[] returned from getServerSideProps — main vulnerability pattern
    {
      filename: path.join(FIXTURES, 'vulnerable-pages.tsx'),
      code: `
        import { getUsers } from './db';

        export const getServerSideProps = async () => {
          const users = await getUsers();
          return { props: { users } };
        };
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
    // Single User object (not array)
    {
      filename: path.join(FIXTURES, 'vulnerable-single.tsx'),
      code: `
        import { getUserById } from './db';

        export const getServerSideProps = async () => {
          const user = await getUserById(1);
          return { props: { user } };
        };
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
    // getStaticProps — same rule applies
    {
      filename: path.join(FIXTURES, 'vulnerable-gsp.tsx'),
      code: `
        import { getUsers } from './db';

        export const getStaticProps = async () => {
          const users = await getUsers();
          return { props: { users } };
        };
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
    // FunctionDeclaration form (not arrow function)
    {
      filename: path.join(FIXTURES, 'vulnerable-fn-decl.tsx'),
      code: `
        import { getUsers } from './db';

        export async function getServerSideProps() {
          const users = await getUsers();
          return { props: { users } };
        }
      `,
      errors: [{ messageId: 'sensitiveFieldExposed' }],
    },
  ],
});

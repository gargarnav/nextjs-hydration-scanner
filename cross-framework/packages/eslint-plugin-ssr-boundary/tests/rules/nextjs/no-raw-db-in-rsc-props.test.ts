import { RuleTester } from '@typescript-eslint/rule-tester';
import { afterAll, describe, it } from 'vitest';
import path from 'node:path';
import { noRawDbInRscProps } from '../../../src/rules/nextjs/no-raw-db-in-rsc-props.js';

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

ruleTester.run('no-raw-db-in-rsc-props', noRawDbInRscProps, {
  valid: [
    // DTO transform applied — PublicUser[] has no sensitive fields
    {
      filename: path.join(FIXTURES, 'secure-rsc.tsx'),
      code: `
        import { getUsers } from './db';
        import { toPublicUsers, PublicUser } from './dto';

        declare function ClientComponent(props: { users: PublicUser[] }): JSX.Element;

        export default async function Page() {
          const users = await getUsers();
          return <ClientComponent users={toPublicUsers(users)} />;
        }
      `,
    },
    // Primitive prop — no sensitive fields
    {
      filename: path.join(FIXTURES, 'primitive-rsc.tsx'),
      code: `
        declare function Widget(props: { title: string; count: number }): JSX.Element;

        export default function Page() {
          return <Widget title="Hello" count={42} />;
        }
      `,
    },
    // String literal expression — never has properties
    {
      filename: path.join(FIXTURES, 'string-literal-rsc.tsx'),
      code: `
        declare function Label(props: { text: string }): JSX.Element;

        export default function Page() {
          const label = 'hello';
          return <Label text={label} />;
        }
      `,
    },
  ],

  invalid: [
    // Raw User[] passed as JSX prop
    {
      filename: path.join(FIXTURES, 'vulnerable-rsc.tsx'),
      code: `
        import { getUsers } from './db';
        import type { User } from './db';

        declare function UserList(props: { users: User[] }): JSX.Element;

        export default async function Page() {
          const users = await getUsers();
          return <UserList users={users} />;
        }
      `,
      errors: [{ messageId: 'sensitiveFieldInJsxProp' }],
    },
    // Single User object passed as prop
    {
      filename: path.join(FIXTURES, 'vulnerable-rsc-single.tsx'),
      code: `
        import { getUserById } from './db';
        import type { User } from './db';

        declare function UserCard(props: { user: User | null }): JSX.Element;

        export default async function Page() {
          const user = await getUserById(1);
          return <UserCard user={user} />;
        }
      `,
      errors: [{ messageId: 'sensitiveFieldInJsxProp' }],
    },
  ],
});

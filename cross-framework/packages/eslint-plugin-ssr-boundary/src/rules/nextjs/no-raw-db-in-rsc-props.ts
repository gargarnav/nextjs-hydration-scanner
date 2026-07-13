import { ESLintUtils, TSESTree } from '@typescript-eslint/utils';
import { isSensitiveFieldName } from '../../utils/sensitive-fields.js';
import { getTypePropertyNames } from '../../utils/type-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  name =>
    `https://github.com/gargarnav/ssr-boundary/blob/main/docs/rules/nextjs-${name}.md`,
);

type MessageIds = 'sensitiveFieldInJsxProp';
type Options = [{ sensitiveFields?: string[] }?];

export const noRawDbInRscProps = createRule<Options, MessageIds>({
  name: 'no-raw-db-in-rsc-props',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow passing props with sensitive fields to JSX components. In Next.js App Router, ' +
        'props passed to Client Components (\'use client\') are serialized into the RSC payload ' +
        'and exposed to every HTTP client. ' +
        'NOTE (v0.1): This rule flags all JSX props with sensitive types, including Server→Server. ' +
        'A false-positive suppression comment (// eslint-disable-next-line) is safe for confirmed ' +
        'Server-to-Server cases. v0.2 will add \'use client\' boundary detection.',
    },
    schema: [
      {
        type: 'object',
        properties: {
          sensitiveFields: {
            type: 'array',
            items: { type: 'string' },
          },
        },
        additionalProperties: false,
      },
    ],
    messages: {
      sensitiveFieldInJsxProp:
        'Type "{{typeName}}" passed as JSX prop "{{propName}}" contains sensitive field "{{fieldName}}" ({{severity}}). ' +
        'If this crosses a Server→Client boundary, apply a DTO transform before passing. ' +
        '(v0.1 limitation: also fires on Server→Server props — suppress with eslint-disable if intentional.)',
    },
  },
  defaultOptions: [{}],
  create(context) {
    const services = ESLintUtils.getParserServices(context);
    const checker = services.program.getTypeChecker();
    const extraFields = new Set(
      (context.options[0]?.sensitiveFields ?? []).map((s: string) => s.toLowerCase()),
    );

    function isSensitive(name: string) {
      const match = isSensitiveFieldName(name);
      if (match) return match;
      if (extraFields.has(name.toLowerCase())) return { severity: 'CUSTOM', label: name };
      return null;
    }

    return {
      JSXExpressionContainer(node: TSESTree.JSXExpressionContainer) {
        if (node.expression.type === 'JSXEmptyExpression') return;

        // Get the parent JSXAttribute to know the prop name
        const parent = node.parent;
        if (!parent || parent.type !== 'JSXAttribute') return;

        const propNameNode = parent.name;
        const propName =
          propNameNode.type === 'JSXIdentifier' ? propNameNode.name : String(propNameNode);

        const tsNode = services.esTreeNodeToTSNodeMap.get(node.expression as TSESTree.Node);
        if (!tsNode) return;

        const type = checker.getTypeAtLocation(tsNode);
        const propNames = getTypePropertyNames(type, checker);

        for (const name of propNames) {
          const match = isSensitive(name);
          if (match) {
            context.report({
              node: node.expression as TSESTree.Node,
              messageId: 'sensitiveFieldInJsxProp',
              data: {
                typeName: checker.typeToString(type),
                propName,
                fieldName: name,
                severity: match.severity,
              },
            });
            break;
          }
        }
      },
    };
  },
});

import { ESLintUtils, TSESTree } from '@typescript-eslint/utils';
import { isSensitiveFieldName } from '../../utils/sensitive-fields.js';
import { getTypePropertyNames } from '../../utils/type-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  name =>
    `https://github.com/gargarnav/ssr-boundary/blob/main/docs/rules/nextjs-${name}.md`,
);

type MessageIds = 'sensitiveFieldExposed';

type Options = [
  {
    sensitiveFields?: string[];
  }?,
];

export const noRawDbInGssp = createRule<Options, MessageIds>({
  name: 'no-raw-db-in-gssp',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow returning raw database types with sensitive fields from getServerSideProps or getStaticProps. ' +
        'Sensitive fields in the returned type will be serialized into __NEXT_DATA__ and exposed to every HTTP client.',
    },
    schema: [
      {
        type: 'object',
        properties: {
          sensitiveFields: {
            type: 'array',
            items: { type: 'string' },
            description: 'Additional field names to treat as sensitive beyond the built-in list.',
          },
        },
        additionalProperties: false,
      },
    ],
    messages: {
      sensitiveFieldExposed:
        'Type "{{typeName}}" passed to {{fnName}} props contains sensitive field "{{fieldName}}" ({{severity}}). ' +
        'Apply a DTO transform (e.g. toPublicUser()) before returning props to strip sensitive fields.',
    },
  },
  defaultOptions: [{}],
  create(context) {
    const services = ESLintUtils.getParserServices(context);
    const checker = services.program.getTypeChecker();

    const extraFields = new Set(
      (context.options[0]?.sensitiveFields ?? []).map((s: string) => s.toLowerCase()),
    );

    function isSensitive(name: string): { severity: string; label: string } | null {
      const match = isSensitiveFieldName(name);
      if (match) return match;
      if (extraFields.has(name.toLowerCase())) return { severity: 'CUSTOM', label: name };
      return null;
    }

    // Tracks which function we are currently inside (if it's a GSSP/GSP)
    let currentGsspName: string | null = null;

    function enterGssp(name: string) {
      currentGsspName = name;
    }

    function exitGssp() {
      currentGsspName = null;
    }

    function checkPropsObject(
      propsValue: TSESTree.Expression | TSESTree.SpreadElement,
      fnName: string,
    ) {
      if (propsValue.type !== 'ObjectExpression') return;

      for (const prop of propsValue.properties) {
        if (prop.type !== 'Property') continue;
        // In a return object literal, value is always an Expression (not AssignmentPattern)
        // but TSESTree types it as Expression | AssignmentPattern for destructuring contexts
        const propValue = prop.value;
        if (propValue.type === 'AssignmentPattern') continue;

        const valueTsNode = services.esTreeNodeToTSNodeMap.get(propValue);
        if (!valueTsNode) continue;

        const type = checker.getTypeAtLocation(valueTsNode);
        const propNames = getTypePropertyNames(type, checker);

        for (const propName of propNames) {
          const match = isSensitive(propName);
          if (match) {
            context.report({
              node: prop.value as TSESTree.Node,
              messageId: 'sensitiveFieldExposed',
              data: {
                typeName: checker.typeToString(type),
                fnName,
                fieldName: propName,
                severity: match.severity,
              },
            });
            break; // one report per prop value — don't flood with every sensitive field
          }
        }
      }
    }

    function checkReturnStatement(node: TSESTree.ReturnStatement, fnName: string) {
      if (!node.argument) return;
      const arg = node.argument;

      // Pattern: return { props: { ... } }
      if (arg.type !== 'ObjectExpression') return;

      const propsProperty = arg.properties.find(
        (p): p is TSESTree.Property =>
          p.type === 'Property' &&
          !p.computed &&
          p.key.type === 'Identifier' &&
          (p.key as TSESTree.Identifier).name === 'props',
      );

      if (!propsProperty) return;
      checkPropsObject(propsProperty.value as TSESTree.Expression, fnName);
    }

    const GSSP_NAMES = /^get(ServerSideProps|StaticProps)$/;

    return {
      // export const getServerSideProps = ...
      'ExportNamedDeclaration > VariableDeclaration > VariableDeclarator'(
        node: TSESTree.VariableDeclarator,
      ) {
        if (
          node.id.type === 'Identifier' &&
          GSSP_NAMES.test(node.id.name)
        ) {
          enterGssp(node.id.name);
        }
      },

      // export async function getServerSideProps() { ... }
      'ExportNamedDeclaration > FunctionDeclaration'(node: TSESTree.FunctionDeclaration) {
        if (node.id && GSSP_NAMES.test(node.id.name)) {
          enterGssp(node.id.name);
        }
      },

      ReturnStatement(node: TSESTree.ReturnStatement) {
        if (currentGsspName) {
          checkReturnStatement(node, currentGsspName);
        }
      },

      'ExportNamedDeclaration:exit'() {
        exitGssp();
      },
    };
  },
});

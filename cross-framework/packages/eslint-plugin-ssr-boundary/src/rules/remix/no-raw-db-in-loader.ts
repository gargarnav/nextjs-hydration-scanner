import { ESLintUtils, TSESTree } from '@typescript-eslint/utils';
import { isSensitiveFieldName } from '../../utils/sensitive-fields.js';
import { getTypePropertyNames } from '../../utils/type-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  name =>
    `https://github.com/gargarnav/ssr-boundary/blob/main/docs/rules/remix-${name}.md`,
);

type MessageIds = 'sensitiveFieldExposed';
type Options = [{ sensitiveFields?: string[] }?];

export const noRawDbInLoader = createRule<Options, MessageIds>({
  name: 'no-raw-db-in-loader',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow returning raw database types with sensitive fields from Remix loader() functions. ' +
        'Return values from loader() are serialized into window.__remixContext and exposed to every HTTP client.',
    },
    schema: [
      {
        type: 'object',
        properties: {
          sensitiveFields: { type: 'array', items: { type: 'string' } },
        },
        additionalProperties: false,
      },
    ],
    messages: {
      sensitiveFieldExposed:
        'Type "{{typeName}}" returned from Remix loader() contains sensitive field "{{fieldName}}" ({{severity}}). ' +
        'Apply a DTO transform before returning to prevent serialization into window.__remixContext.',
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

    let insideLoader = false;

    function checkNode(node: TSESTree.Node) {
      const tsNode = services.esTreeNodeToTSNodeMap.get(node);
      if (!tsNode) return;
      const type = checker.getTypeAtLocation(tsNode);

      // Check properties of the returned object type
      const objectProps = checker.getPropertiesOfType(type);
      for (const prop of objectProps) {
        const propType = checker.getTypeOfSymbol(prop);
        const names = getTypePropertyNames(propType, checker);
        for (const name of names) {
          const match = isSensitive(name);
          if (match) {
            context.report({
              node,
              messageId: 'sensitiveFieldExposed',
              data: {
                typeName: checker.typeToString(propType),
                fieldName: name,
                severity: match.severity,
              },
            });
            return; // one report per return statement
          }
        }
      }

      // Also check if the type itself (not its props) is a sensitive array/object
      const names = getTypePropertyNames(type, checker);
      for (const name of names) {
        const match = isSensitive(name);
        if (match) {
          context.report({
            node,
            messageId: 'sensitiveFieldExposed',
            data: {
              typeName: checker.typeToString(type),
              fieldName: name,
              severity: match.severity,
            },
          });
          return;
        }
      }
    }

    function checkReturnStatement(node: TSESTree.ReturnStatement) {
      if (!node.argument) return;
      const arg = node.argument;

      // Case 1: return json({ users }) or return Response.json({ users })
      if (arg.type === 'CallExpression') {
        const callee = arg.callee;
        const isJsonHelper =
          (callee.type === 'Identifier' && callee.name === 'json') ||
          (callee.type === 'MemberExpression' &&
            callee.property.type === 'Identifier' &&
            (callee.property as TSESTree.Identifier).name === 'json');

        if (isJsonHelper && arg.arguments.length > 0) {
          checkNode(arg.arguments[0] as TSESTree.Node);
          return;
        }
      }

      // Case 2: return { users } directly
      checkNode(arg);
    }

    return {
      'ExportNamedDeclaration > VariableDeclaration > VariableDeclarator'(
        node: TSESTree.VariableDeclarator,
      ) {
        if (node.id.type === 'Identifier' && node.id.name === 'loader') {
          insideLoader = true;
        }
      },
      'ExportNamedDeclaration > FunctionDeclaration'(node: TSESTree.FunctionDeclaration) {
        if (node.id?.name === 'loader') {
          insideLoader = true;
        }
      },
      ReturnStatement(node: TSESTree.ReturnStatement) {
        if (insideLoader) checkReturnStatement(node);
      },
      'ExportNamedDeclaration:exit'() {
        insideLoader = false;
      },
    };
  },
});

import { ESLintUtils, TSESTree } from '@typescript-eslint/utils';
import { isSensitiveFieldName } from '../../utils/sensitive-fields.js';
import { getTypePropertyNames } from '../../utils/type-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  name =>
    `https://github.com/gargarnav/ssr-boundary/blob/main/docs/rules/sveltekit-${name}.md`,
);

type MessageIds = 'sensitiveFieldExposed';
type Options = [{ sensitiveFields?: string[] }?];

// Matches SvelteKit server files: +page.server.ts, +layout.server.ts (and .js variants)
const SVELTEKIT_SERVER_FILE_RE = /\+(page|layout)\.server\.[cm]?[jt]sx?$/;

export const noRawDbInLoad = createRule<Options, MessageIds>({
  name: 'no-raw-db-in-load',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow returning raw database types with sensitive fields from SvelteKit load() functions. ' +
        'Return values from load() in +page.server.ts / +layout.server.ts are serialized into ' +
        '__sveltekit_data and exposed to every HTTP client.',
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
        'Type "{{typeName}}" returned from SvelteKit load() contains sensitive field "{{fieldName}}" ({{severity}}). ' +
        'Apply a DTO transform before returning to prevent serialization into __sveltekit_data.',
    },
  },
  defaultOptions: [{}],
  create(context) {
    // Only activate in SvelteKit server files
    const filename = context.filename ?? context.getFilename?.() ?? '';
    if (!SVELTEKIT_SERVER_FILE_RE.test(filename)) {
      return {};
    }

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

    let insideLoad = false;

    function checkReturnValue(node: TSESTree.ReturnStatement) {
      if (!node.argument) return;
      const tsNode = services.esTreeNodeToTSNodeMap.get(node.argument);
      if (!tsNode) return;
      const type = checker.getTypeAtLocation(tsNode);

      // The return value of load() is an object — check each property's type
      const props = checker.getPropertiesOfType(type);
      for (const prop of props) {
        const propType = checker.getTypeOfSymbol(prop);
        const names = getTypePropertyNames(propType, checker);
        for (const name of names) {
          const match = isSensitive(name);
          if (match) {
            context.report({
              node: node.argument!,
              messageId: 'sensitiveFieldExposed',
              data: {
                typeName: checker.typeToString(propType),
                fieldName: name,
                severity: match.severity,
              },
            });
            break;
          }
        }
      }
    }

    return {
      // export const load = ...
      'ExportNamedDeclaration > VariableDeclaration > VariableDeclarator'(
        node: TSESTree.VariableDeclarator,
      ) {
        if (node.id.type === 'Identifier' && node.id.name === 'load') {
          insideLoad = true;
        }
      },
      // export async function load() { ... }
      'ExportNamedDeclaration > FunctionDeclaration'(node: TSESTree.FunctionDeclaration) {
        if (node.id?.name === 'load') {
          insideLoad = true;
        }
      },
      ReturnStatement(node: TSESTree.ReturnStatement) {
        if (insideLoad) checkReturnValue(node);
      },
      'ExportNamedDeclaration:exit'() {
        insideLoad = false;
      },
    };
  },
});

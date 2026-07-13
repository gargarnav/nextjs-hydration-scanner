import { ESLintUtils, TSESTree } from '@typescript-eslint/utils';
import { isSensitiveFieldName } from '../../utils/sensitive-fields.js';
import { getTypePropertyNames } from '../../utils/type-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  name =>
    `https://github.com/gargarnav/ssr-boundary/blob/main/docs/rules/nuxt-${name}.md`,
);

type MessageIds = 'sensitiveFieldExposed';
type Options = [{ sensitiveFields?: string[] }?];

// Nuxt server route files: server/api/*.ts, server/routes/*.ts
const NUXT_SERVER_FILE_RE = /server\/(api|routes)\//;

export const noRawDbInAsyncData = createRule<Options, MessageIds>({
  name: 'no-raw-db-in-async-data',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow returning raw database types with sensitive fields from Nuxt server API handlers. ' +
        'Return values from defineEventHandler() in server/api/ and server/routes/ are serialized ' +
        'into __NUXT_DATA__ / window.__NUXT__ and exposed to every HTTP client. ' +
        'NOTE (v0.1): Targets server/api/*.ts files. Vue SFC useAsyncData support coming in v0.2.',
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
        'Type "{{typeName}}" returned from Nuxt defineEventHandler() contains sensitive field "{{fieldName}}" ({{severity}}). ' +
        'Apply a DTO transform before returning to prevent serialization into __NUXT_DATA__.',
    },
  },
  defaultOptions: [{}],
  create(context) {
    // Only activate in Nuxt server files
    const filename = context.filename ?? context.getFilename?.() ?? '';
    if (!NUXT_SERVER_FILE_RE.test(filename)) {
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

    let insideEventHandler = false;

    function checkReturn(node: TSESTree.ReturnStatement) {
      if (!node.argument) return;
      const tsNode = services.esTreeNodeToTSNodeMap.get(node.argument);
      if (!tsNode) return;
      const type = checker.getTypeAtLocation(tsNode);
      const names = getTypePropertyNames(type, checker);

      for (const name of names) {
        const match = isSensitive(name);
        if (match) {
          context.report({
            node: node.argument!,
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

    return {
      // export default defineEventHandler(async (event) => { ... })
      'ExportDefaultDeclaration > CallExpression[callee.name="defineEventHandler"]'() {
        insideEventHandler = true;
      },
      'ExportDefaultDeclaration > CallExpression[callee.name="defineEventHandler"]:exit'() {
        insideEventHandler = false;
      },
      ReturnStatement(node: TSESTree.ReturnStatement) {
        if (insideEventHandler) checkReturn(node);
      },
    };
  },
});

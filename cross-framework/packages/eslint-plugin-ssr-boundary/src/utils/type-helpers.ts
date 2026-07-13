import type * as ts from 'typescript';

/**
 * Returns all string property names of a TypeScript type.
 *
 * Handles:
 * - Array types: T[] or ReadonlyArray<T> → unwraps to T
 * - Promise types: Promise<T> → unwraps to T
 * - Union types: A | B → collects from all members
 * - Intersection types: A & B → collects from all members
 * - Regular object types: enumerates getPropertiesOfType
 */
export function getTypePropertyNames(
  type: ts.Type,
  checker: ts.TypeChecker,
  _seen = new Set<ts.Type>(),
): string[] {
  // Guard against infinite recursion on recursive types
  if (_seen.has(type)) return [];
  _seen.add(type);

  // Unwrap array: T[] or ReadonlyArray<T> → T
  if (checker.isArrayType(type)) {
    const typeArgs = checker.getTypeArguments(type as ts.TypeReference);
    if (typeArgs.length > 0) {
      return getTypePropertyNames(typeArgs[0]!, checker, _seen);
    }
    return [];
  }

  // Unwrap readonly array (Readonly<Array<T>>)
  if ((type as ts.TypeReference).target) {
    const symbol = type.getSymbol();
    if (symbol && (symbol.getName() === 'ReadonlyArray' || symbol.getName() === 'Array')) {
      const typeArgs = checker.getTypeArguments(type as ts.TypeReference);
      if (typeArgs.length > 0) {
        return getTypePropertyNames(typeArgs[0]!, checker, _seen);
      }
    }
  }

  // Unwrap Promise<T> → T
  const symbol = type.getSymbol();
  if (symbol && symbol.getName() === 'Promise') {
    const typeArgs = checker.getTypeArguments(type as ts.TypeReference);
    if (typeArgs.length > 0) {
      return getTypePropertyNames(typeArgs[0]!, checker, _seen);
    }
  }

  // Handle union: A | B | C
  if (type.isUnion()) {
    const names: string[] = [];
    for (const member of type.types) {
      names.push(...getTypePropertyNames(member, checker, _seen));
    }
    return [...new Set(names)];
  }

  // Handle intersection: A & B
  if (type.isIntersection()) {
    const names: string[] = [];
    for (const member of type.types) {
      names.push(...getTypePropertyNames(member, checker, _seen));
    }
    return [...new Set(names)];
  }

  // Skip primitives and special types that cannot have sensitive object properties.
  // TypeScript TypeFlags (verified against ts 5.x source):
  //   Any=1, Unknown=2, String=4, Number=8, Boolean=16, BigInt=64,
  //   StringLiteral=128, NumberLiteral=256, BooleanLiteral=512,
  //   ESSymbol=4096, UniqueESSymbol=8192,
  //   Void=16384, Undefined=32768, Null=65536, Never=131072, TypeParameter=262144
  // Object=524288 and Union=1048576 are intentionally NOT in this list.
  const PRIMITIVE_FLAGS =
    1 |        // Any
    2 |        // Unknown
    4 |        // String
    8 |        // Number
    16 |       // Boolean
    64 |       // BigInt
    128 |      // StringLiteral
    256 |      // NumberLiteral
    512 |      // BooleanLiteral
    4096 |     // ESSymbol
    8192 |     // UniqueESSymbol
    16384 |    // Void
    32768 |    // Undefined
    65536 |    // Null
    131072 |   // Never
    262144;    // TypeParameter
  if (type.flags & PRIMITIVE_FLAGS) {
    return [];
  }

  // Regular object type: enumerate properties
  const props = checker.getPropertiesOfType(type);
  return props.map(p => p.getName());
}

/**
 * Check whether a TypeScript type (including arrays and unions) has any
 * property whose name is potentially sensitive.
 *
 * Returns the first sensitive property name found, or null.
 */
export function findSensitiveProperty(
  type: ts.Type,
  checker: ts.TypeChecker,
  isSensitive: (name: string) => boolean,
): string | null {
  const names = getTypePropertyNames(type, checker);
  for (const name of names) {
    if (isSensitive(name)) return name;
  }
  return null;
}

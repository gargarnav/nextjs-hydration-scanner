import patternsJson from '../sensitive-patterns.json';

interface FieldPatternEntry {
  pattern: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  label: string;
  is_regex?: boolean;
  flags?: string;
}

interface ValuePatternEntry {
  pattern: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  label: string;
  flags?: string;
}

const data = patternsJson as {
  field_patterns: FieldPatternEntry[];
  value_patterns: ValuePatternEntry[];
};

export interface SensitiveMatch {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  label: string;
}

// Compiled field-name patterns in declaration order (first match wins — most specific first)
const FIELD_PATTERNS: Array<{ re: RegExp; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'; label: string }> =
  data.field_patterns.map(entry => ({
    re: new RegExp(entry.pattern, 'i'),
    severity: entry.severity,
    label: entry.label,
  }));

/**
 * Check whether a TypeScript property name matches any sensitive field pattern.
 * Returns the first (highest-priority) match, or null if no match.
 */
export function isSensitiveFieldName(name: string): SensitiveMatch | null {
  for (const { re, severity, label } of FIELD_PATTERNS) {
    if (re.test(name)) {
      return { severity, label };
    }
  }
  return null;
}

/**
 * Returns all sensitive matches for a property name (for reporting all violations).
 * In practice, only the first is used since patterns are ordered most-specific first.
 */
export function getSensitiveFieldMatches(name: string): SensitiveMatch[] {
  const matches: SensitiveMatch[] = [];
  for (const { re, severity, label } of FIELD_PATTERNS) {
    if (re.test(name)) {
      matches.push({ severity, label });
      break; // first match wins
    }
  }
  return matches;
}

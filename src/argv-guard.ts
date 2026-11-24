/**
 * Pre-dispatch argv guard (CLI-SPEC section 8).
 *
 * Refuses a flag value that looks like key material before any command body
 * runs. The patterns are intentionally narrow: a PEM private-key header, a
 * three-part JWT with a JSON header, and a URL with an inline password.
 */

const SECRET_PATTERNS: readonly RegExp[] = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/i,
];

export function hasSecretInArgv(argv: readonly string[]): boolean {
  return argv.some((arg) => SECRET_PATTERNS.some((pattern) => pattern.test(arg)));
}

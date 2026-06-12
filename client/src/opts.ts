// Strict option-bag validation (issue: silently-ignored options).
//
// SDK methods that take an options object reject unknown keys instead of
// silently ignoring them. A misspelled or unsupported option (e.g. passing
// `display_name` where the SDK expects `label`) previously made an
// integration look correct while doing nothing — the call succeeded and the
// option vanished. Throwing is deliberate and unconditional: the SDK runs in
// browsers where "development vs production" cannot be detected reliably,
// and mode-dependent validation makes tests pass against behavior production
// doesn't have.

/**
 * Throw if `opts` carries any key outside `knownKeys`.
 *
 * Validates only the top-level key set — values are validated by each
 * method's own checks. `null`/`undefined` opts are accepted (methods default
 * the bag to `{}`); any other non-object throws.
 *
 * @param fnName - public method name used to prefix the error message
 * @param opts - the caller-supplied options bag
 * @param knownKeys - the exact set of supported option keys
 */
export function assertKnownOpts(
  fnName: string,
  opts: unknown,
  knownKeys: readonly string[],
): void {
  if (opts == null) return;
  if (typeof opts !== 'object' || Array.isArray(opts)) {
    throw new Error(`${fnName}(): opts must be an object`);
  }
  for (const key of Object.keys(opts)) {
    if (!knownKeys.includes(key)) {
      throw new Error(
        `${fnName}(): unknown option "${key}" — supported options: ${knownKeys.join(', ')}`,
      );
    }
  }
}

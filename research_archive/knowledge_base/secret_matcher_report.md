# Secret Matcher Robustness & Compatibility Report

- **Total patterns**: 931
- **Successfully compiled**: 924
- **Unsupported patterns**: 7
- **Compilation success percentage**: 99.25%

## Reasons unsupported regexes exist
TruffleHog uses Google's RE2 engine while the scanner currently relies on Python's `re` regex engine. Google's RE2 engine supports certain syntax elements that Python's native regex engine does not, such as the `\z` anchor (absolute end of string without newline) or inline modifiers `(?i)` placed in the middle of a regex. Attempting to blindly compile these with `re.compile()` raises an `re.error`.

Unsupported detectors are preserved in the canonical database but excluded from runtime matching. This fault-tolerant design ensures the scanner gracefully falls back and never crashes due to a single incompatible RE2 signature.

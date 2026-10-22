// Guards the "path" a caller wants forwarded to the destination.
//
// A backend may percent-decode a path once, twice or more before it resolves dot segments, so
// no single view of the path is trustworthy. Instead of listing known-bad encodings, the guard
// follows the path through EVERY decoding level until it stops changing (a fixed point) and
// requires each level to pass the same strict check. If every level is safe, the path is safe
// no matter how many times a backend decodes it.
//
// Rules applied to every level:
//  - starts with exactly one "/" (rejects "//host" network-path prefixes, "/\host", and "/ /host"
//    because URL parsers trim leading spaces)
//  - no control characters (NUL, tab, CR, LF, DEL ...): URL parsers silently drop some of them,
//    which turns ".<TAB>." into ".."
//  - no backslash: many servers treat it as "/"
//  - no ".." segment, also when written "..;params" (some servers strip ";params")
//  - no overlong UTF-8 lead bytes (%c0, %c1, ...), the classic encoded-dot bypass
// Delimiters that appear through decoding ("?", "#", "/") are ordinary characters; only a real
// "?" or "#" in the caller's raw string ends the path (the query is not inspected).

const MAX_DECODE_PASSES = 10;
const OVERLONG_UTF8 = /%c[01]|%e0%[89][0-9a-f]|%f0%8[0-9a-f]/i;
const ESCAPE_RUN = /(?:%[0-9a-f]{2})+/gi;

const hasControlChars = (s) => [...s].some((c) => c.codePointAt(0) <= 0x1f || c === '\u007f');

function isUnsafeLevel(level) {
  if (!/^\/(?! *[/\\])/.test(level)) return true;
  if (hasControlChars(level) || level.includes('\\') || OVERLONG_UTF8.test(level)) return true;
  return level.split('/').some((segment) => segment.split(';')[0].trim() === '..');
}

// Decodes every valid UTF-8 escape run. A "%" that is not followed by two hex digits stays
// literal, so legitimate values such as "100%25.csv" (-> "100%.csv") remain usable.
// An escape run that is not valid UTF-8 is a malformed request on the first pass; on later
// passes it is a literal "%XX" that a decoded value happens to contain, and is left as is.
function decodeOnce(level, firstPass) {
  let malformed = false;
  const decoded = level.replace(ESCAPE_RUN, (run) => {
    try {
      return decodeURIComponent(run);
    } catch {
      malformed = true;
      return run;
    }
  });
  return firstPass && malformed ? null : decoded;
}

// Returns true if the path could leave the destination's URL space (or is malformed).
function hasTraversal(path) {
  if (typeof path !== 'string' || hasControlChars(path)) return true;
  let level = path.split(/[?#]/)[0];
  for (let pass = 0; pass <= MAX_DECODE_PASSES; pass++) {
    if (isUnsafeLevel(level)) return true;
    const next = decodeOnce(level, pass === 0);
    if (next === null) return true;
    if (next === level) return false;
    level = next;
  }
  return true; // still changing after MAX_DECODE_PASSES: absurd nesting, treat as unsafe
}

module.exports = { hasTraversal };

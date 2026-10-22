// Validates the "path" a caller wants forwarded to the destination (OWASP-style allowlist).
//
// The path part (everything before the first "?" or "#") must match a strict grammar:
//  - a "/" followed by non-empty segments separated by single "/" (optional trailing "/")
//  - a segment is made only of unreserved characters, a few sub-delimiters (including ";" for
//    matrix parameters like ";v=2"), or one of a fixed set of percent-escapes
//  - the allowed escapes can never decode to ".", "/", "\", "%", "?", "#" or a control character,
//    so a backend decoding once, twice or ten times always sees the same string and no encoding
//    can assemble a traversal, a delimiter or a "//host" prefix
//  - a segment (ignoring ";params") may not be "." or ".."
// Everything outside the grammar is rejected, including "%25", non-ASCII and other escapes.
// The query string is passed through unchanged apart from rejecting control characters.

const PLAIN = "[A-Za-z0-9\\-._~!$&'()*+,;=:@]";
// %20 space, %21 !, %22 ", %24 $, %26 &, %27 ', %28 (, %29 ), %2A *, %2B +, %2C ",", %3A :, %3D =, %40 @
const ESCAPE = '%(?:2[01246-9ABCabc]|3[ADad]|40)';
const TOKEN = `(?:${PLAIN}|${ESCAPE})`;
const PATH_GRAMMAR = new RegExp(`^/(?:${TOKEN}+(?:/${TOKEN}+)*/?)?$`);

const hasControlChars = (s) => [...s].some((c) => c.codePointAt(0) <= 0x1f || c === '\u007f');

function hasTraversal(path) {
  if (typeof path !== 'string' || hasControlChars(path)) return true;
  const pathOnly = path.split(/[?#]/)[0];
  if (!PATH_GRAMMAR.test(pathOnly)) return true;
  return pathOnly.split('/').some((segment) => {
    const name = segment.split(';')[0];
    return name === '.' || name === '..';
  });
}

module.exports = { hasTraversal };

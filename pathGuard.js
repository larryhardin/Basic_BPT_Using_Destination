// Guards the "path" a caller wants forwarded to the destination.
//
// This is an allowlist, not a model of how a backend decodes. Every percent-escape that could
// ever turn into a dot, slash, backslash, "?", "#", ";", a control character, a hex digit or a
// "%" is rejected, so there is nothing a second or third decoding pass could assemble into
// "..", "%2e" or "//host". Whatever decoder the backend uses, the result is the same string.
//
// Rules for the path part (everything before the first real "?" or "#"):
//  - starts with exactly one "/" and no space/separator run after it ("//host", "/\host", "/ /host")
//  - no control characters and no backslash, literal or escaped
//  - no ".." segment (also "..;params"); dots cannot be escaped, so this check is final
//  - escapes only for a small set of harmless ASCII symbols, or for valid UTF-8 (bytes >= 0x80)
//  - "%25" (a literal percent sign) is allowed only when the next two characters are not hex
//    digits, because "%252e" would otherwise decode to "%2e"
// The query string after the first real "?" or "#" is not inspected.

const HEX_PAIR = /^[0-9a-f]{2}$/i;

// Escapes allowed for ASCII bytes: space ! " $ & ' ( ) * + , - : = @ < > [ ] ^ _ ` { | } ~
const SAFE_ASCII_ESCAPES = new Set([
  0x20, 0x21, 0x22, 0x24, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x3a, 0x3c, 0x3d, 0x3e,
  0x40, 0x5b, 0x5d, 0x5e, 0x5f, 0x60, 0x7b, 0x7c, 0x7d, 0x7e
]);

const hasControlChars = (s) => [...s].some((c) => c.codePointAt(0) <= 0x1f || c === '\u007f');

function escapesAreSafe(path) {
  for (let i = 0; i < path.length; i++) {
    if (path[i] !== '%') continue;
    const hex = path.slice(i + 1, i + 3);
    if (!HEX_PAIR.test(hex)) continue; // a lone "%" is just a literal character
    const byte = parseInt(hex, 16);
    if (byte >= 0x80) {
      // Consume the whole run of high-byte escapes and require valid (non-overlong) UTF-8
      let end = i;
      while (/^%[89a-f][0-9a-f]/i.test(path.slice(end, end + 3))) end += 3;
      try {
        decodeURIComponent(path.slice(i, end));
      } catch {
        return false;
      }
      i = end - 1;
    } else if (byte === 0x25) {
      if (HEX_PAIR.test(path.slice(i + 3, i + 5))) return false;
      i += 2;
    } else if (SAFE_ASCII_ESCAPES.has(byte)) {
      i += 2;
    } else {
      return false;
    }
  }
  return true;
}

function hasTraversal(path) {
  if (typeof path !== 'string') return true;
  const pathOnly = path.split(/[?#]/)[0];
  if (hasControlChars(path) || pathOnly.includes('\\')) return true;
  if (!/^\/(?! *[/\\])/.test(pathOnly)) return true;
  if (!escapesAreSafe(pathOnly)) return true;
  // After the checks above one decoding pass is the only one that can change anything
  const decoded = pathOnly.replace(/(?:%[0-9a-f]{2})+/gi, (run) => decodeURIComponent(run));
  if (!/^\/(?! *[/\\])/.test(decoded) || hasControlChars(decoded)) return true;
  return decoded.split('/').some((segment) => segment.split(';')[0].trim() === '..');
}

module.exports = { hasTraversal };

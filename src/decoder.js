// mona.expert — Input Decoder Layer
// Detects and normalizes encoded/homoglyph attacks before injection guard analysis

// ─── Unicode Homoglyph Map ────────────────────────────────────────
// Maps common Cyrillic, Greek, and Unicode lookalikes to their ASCII equivalents
const HOMOGLYPH_MAP = {
  // Cyrillic small letters that look like Latin
  'а': 'a', 'е': 'e', 'о': 'o', 'с': 'c', 'р': 'p', 'х': 'x',
  'у': 'y', 'і': 'i', 'ј': 'j', 'к': 'k', 'м': 'm', 'н': 'h',
  'в': 'b', 'т': 't', 'г': 'r', 'ѕ': 's', 'ѡ': 'w',
  // Cyrillic capitals
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H',
  'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X',
  'Г': 'R', 'Ѕ': 'S', 'І': 'I', 'Ї': 'I',
  // Greek lookalikes
  'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'κ': 'k', 'μ': 'm',
  'ν': 'h', 'ο': 'o', 'π': 'n', 'ρ': 'p', 'τ': 't', 'χ': 'x',
  // Common leetspeak substitutions
  '0': 'o', '1': 'l', '2': 'z', '3': 'e', '4': 'a', '5': 's',
  '6': 'g', '7': 't', '8': 'b', '9': 'g',
  '@': 'a', '$': 's', '!': 'i', '+': 't', '#': 'h',
  // Special Unicode spaces that can hide tokens
  '\u200B': '', '\u200C': '', '\u200D': '', '\uFEFF': '',
  '\u00A0': ' ', '\u2000': ' ', '\u2001': ' ', '\u2002': ' ',
  '\u2003': ' ', '\u2004': ' ', '\u2005': ' ', '\u2006': ' ',
  '\u2007': ' ', '\u2008': ' ', '\u2009': ' ', '\u200A': ' ',
  // Invisible separators
  '\u2060': '', '\u2061': '', '\u2062': '', '\u2063': '', '\u2064': '',
};

// ─── Encoded Payload Detectors ────────────────────────────────────

/**
 * Normalize homoglyphs and leetspeak in input text.
 * Returns { normalized, hadHomoglyphs, hadLeetspeak }
 */
function normalizeHomoglyphs(input) {
  if (typeof input !== "string") return { normalized: "", hadHomoglyphs: false, hadLeetspeak: false };
  
  let hadHomoglyphs = false;
  let hadLeetspeak = false;
  const leetspeakChars = new Set(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '@', '$', '!', '+', '#']);
  
  const normalized = Array.from(input).map(ch => {
    const replacement = HOMOGLYPH_MAP[ch];
    if (replacement !== undefined) {
      if (replacement === '') {
        hadHomoglyphs = true; // zero-width chars
        return replacement;
      }
      if (ch !== replacement && leetspeakChars.has(ch)) {
        hadLeetspeak = true;
      } else if (ch !== replacement) {
        hadHomoglyphs = true;
      }
      return replacement;
    }
    return ch;
  }).join('');
  
  return { normalized, hadHomoglyphs, hadLeetspeak };
}

/**
 * Try to decode base64 substrings within input text.
 * Extracts potential base64 sequences and decodes each one.
 * Returns decoded text from the first valid result, or null.
 */
function tryDecodeBase64(input) {
  // Find all base64-like sequences (12+ alphanumeric+/ chars, optional padding)
  const b64Chunks = input.match(/[A-Za-z0-9+/]{12,}={0,2}/g);
  if (!b64Chunks) return null;
  
  for (const chunk of b64Chunks) {
    // Skip chunks that are shorter than 12 after removing padding
    const core = chunk.replace(/=+$/, '');
    if (core.length < 12) continue;
    
    try {
      const decoded = Buffer.from(chunk, 'base64').toString('utf-8');
      // Check it looks like text: at least 60% printable ASCII
      let printable = 0;
      for (let i = 0; i < decoded.length; i++) {
        const code = decoded.charCodeAt(i);
        if (code >= 32 && code <= 126) printable++;
      }
      if (printable < decoded.length * 0.6) continue;
      if (decoded.length < 8) continue;
      return decoded;
    } catch {
      continue;
    }
  }
  
  return null;
}

/**
 * Try to decode hex substrings within input text.
 * Extracts potential hex sequences (12+ hex chars) and decodes each one.
 */

/**
 * Try to decode URL-encoded (%XX) substrings within input text.
 * Extracts potential URL-encoded sequences and decodes them.
 */
function tryDecodeURL(input) {
  // Only attempt if at least one %XX pattern exists
  if (!/%[0-9a-fA-F]{2}/.test(input)) return null;

  try {
    const decoded = decodeURIComponent(input);
    if (decoded === input) return null;
    // Check it looks like meaningful text and contains known trigger words
    let printable = 0;
    for (let i = 0; i < decoded.length; i++) {
      const code = decoded.charCodeAt(i);
      if (code >= 32 && code <= 126) printable++;
    }
    if (printable < decoded.length * 0.5) return null;
    if (decoded.length < 10) return null;
    return decoded;
  } catch {
    return null;
  }
}

/**
 * Try to decode hex substrings within input text.
 * Extracts potential hex sequences (12+ hex chars) and decodes each one.
 */
function tryDecodeHex(input) {
  // Find all hex-like sequences (12+ consecutive hex chars)
  // Also support 0x-prefixed
  const hexChunks = input.match(/(?:0x)?[0-9a-fA-F]{12,}/g);
  if (!hexChunks) return null;
  
  for (const chunk of hexChunks) {
    const stripped = chunk.replace(/^0x/, '');
    // Must be even length for valid hex encoding
    if (stripped.length < 12 || stripped.length % 2 !== 0) continue;
    
    try {
      const decoded = Buffer.from(stripped, 'hex').toString('utf-8');
      let printable = 0;
      for (let i = 0; i < decoded.length; i++) {
        const code = decoded.charCodeAt(i);
        if (code >= 32 && code <= 126) printable++;
      }
      if (printable < decoded.length * 0.6) continue;
      if (decoded.length < 6) continue;
      return decoded;
    } catch {
      continue;
    }
  }
  
  return null;
}

/**
 * Detect and decode common obfuscation patterns:
 * - character-separated commands (i.g.n.o.r.e)
 * - spaces between every character (i g n o r e)
 * - reverse text (erongi)
 */
function tryDecodeObfuscation(input) {
  const results = [];
  
  // Pattern 1: Dotted/separated words: i.g.n.o.r.e or i-g-n-o-r-e within larger text
  // Find sequences like c.h.a.r. or c-h-a-r- with 4+ separated chars
  const separatedWords = input.match(/\b[a-zA-Z0-9](?:[-._~|:;,\s][a-zA-Z0-9]){4,}\b/g);
  if (separatedWords) {
    for (const word of separatedWords) {
      const decoded = word.replace(/[-._~|:;,\s]/g, '');
      if (decoded.length > 4 && /^[a-zA-Z]+$/.test(decoded)) {
        // Replace obfuscated word in full input to reconstruct the sentence
        const fullReconstructed = input.replace(word, decoded);
        results.push(fullReconstructed);
      }
    }
  }
  
  // Pattern 2: Reverse text check (entire input or long segments)
  // Only for inputs that are primarily reversed English
  const reversed = input.split('').reverse().join('');
  if (/^[a-zA-Z\s]+$/.test(reversed) && /(?:ignore|reveal|forget|system|prompt|override|restriction|bypass|secret|password|instruction|command)/i.test(reversed)) {
    results.push(reversed);
  }
  
  return results.length > 0 ? results : null;
}

/**
 * Full decode pipeline: tries all decoding strategies in sequence.
 * Returns array of { source, text } for each successfully decoded variant.
 */
function decodeAll(input) {
  const results = [];
  
  // 1. Homoglyph normalization
  const { normalized, hadHomoglyphs, hadLeetspeak } = normalizeHomoglyphs(input);
  if (hadHomoglyphs || hadLeetspeak) {
    results.push({ source: 'homoglyph', text: normalized });
  }
  
  // 2. Base64 decode
  const b64 = tryDecodeBase64(input);
  if (b64) {
    results.push({ source: 'base64', text: b64 });
  }
  
  // 3. Hex decode
  const hex = tryDecodeHex(input);
  if (hex) {
    results.push({ source: 'hex', text: hex });
  }
  
  // 4. URL decode
  const url = tryDecodeURL(input);
  if (url) {
    results.push({ source: 'url', text: url });
  }

  // 5. Obfuscation decode (dotted, spaced, reversed)
  const obfuscated = tryDecodeObfuscation(input);
  if (obfuscated) {
    obfuscated.forEach(t => results.push({ source: 'obfuscation', text: t }));
  }
  
  return results;
}

export {
  normalizeHomoglyphs,
  tryDecodeBase64,
  tryDecodeHex,
  tryDecodeURL,
  tryDecodeObfuscation,
  decodeAll,
  HOMOGLYPH_MAP,
};

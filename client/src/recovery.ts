// Tarn Client — Account-key primitive (issue #12)
//
// BIP39-style account-key generation, recovery KEK derivation, PDF
// rendering, and the account-recovery flow. All operations are client-side
// — the Tarn API never sees the account key, the entropy, the KEK, or the
// rendered PDF. Apps that want to deliver the kit out-of-band (email,
// download, print) do so themselves.

import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

// 24-word account key = 256 bits of entropy. Per the design doc this is the
// stronger choice over 12-word; the account key is the user's permanent
// vault key and we want the entropy budget to be comfortable.
const PHRASE_STRENGTH_BITS = 256;

// ============ ACCOUNT KEY GENERATION + VALIDATION ============

/**
 * Generate a fresh 24-word BIP39 mnemonic account key using cryptographically
 * secure randomness. Returns a single space-separated string.
 */
export function generateAccountKey(): string {
  return generateMnemonic(wordlist, PHRASE_STRENGTH_BITS);
}

/** Result of account-key validation. `normalized` is filled even on failure (best-effort). */
export type PhraseValidation =
  | { valid: true; normalized: string }
  | { valid: false; normalized: string; reason: string };

/**
 * Validate an account key against the BIP39 English wordlist (word membership +
 * checksum). The user-typed key is normalized — leading/trailing
 * whitespace trimmed, internal whitespace collapsed, lowercased — before
 * validation, mirroring the normalization applied during recovery KEK
 * derivation.
 */
export function validateAccountKey(phrase: string): PhraseValidation {
  if (!phrase || typeof phrase !== 'string') {
    return { valid: false, normalized: '', reason: 'account key must be a non-empty string' };
  }
  const normalized = normalizePhrase(phrase);
  const words = normalized.split(' ');
  if (words.length !== 24) {
    return { valid: false, normalized, reason: `expected 24 words, got ${words.length}` };
  }
  if (!validateMnemonic(normalized, wordlist)) {
    return { valid: false, normalized, reason: 'invalid BIP39 mnemonic (word not in list, or checksum mismatch)' };
  }
  return { valid: true, normalized };
}

/**
 * Recover the raw entropy bytes from an account key. Useful for tests and for
 * sharing-protocol §14.11 work where the account key will derive an
 * additional sub-key — the entropy is the canonical seed, not the derived
 * recovery KEK.
 */
export function accountKeyToEntropy(phrase: string): Uint8Array {
  const v = validateAccountKey(phrase);
  if (!v.valid) throw new Error(`Invalid account key: ${v.reason}`);
  return mnemonicToEntropy(v.normalized, wordlist);
}

function normalizePhrase(phrase: string): string {
  // Match the BIP39 spec normalization used in deriveRecoveryKey: NFKD,
  // lowercase, collapse whitespace to single spaces, trim.
  return phrase.normalize('NFKD').toLowerCase().trim().split(/\s+/).join(' ');
}

// ============ PDF RENDERING (zero-dep, vendored generator) ============
//
// We intentionally do not depend on a third-party PDF library. The output we
// need is a single page of static text — title, branding line, the 24-word
// account key laid out in a 6×4 numbered grid, instructions, and an explicit
// "save and delete this email" nudge. A hand-rolled PDF keeps the client
// bundle small (no jsPDF/pdf-lib pull), and the generator is short enough
// that its correctness is easy to audit.
//
// PDF version: 1.4. Built-in Helvetica font — no font embedding needed.
// Page size: US Letter (612×792 points).

const PAGE_W = 612;
const PAGE_H = 792;
const MARGIN = 54; // 0.75"

type FontId = 'F1' | 'F2' | 'F3';

type TextRun = {
  /** Optional explicit x-coordinate; defaults to MARGIN. */
  x?: number;
  y: number;
  font: FontId;
  size: number;
  text: string;
};

export type RenderRecoveryOpts = {
  phrase: string;
  appName?: string;
  /** ISO date (YYYY-MM-DD) or other display string; defaults to today. */
  generatedAt?: string;
};

/**
 * Render the recovery PDF for an account key + optional branding metadata.
 * Returns the raw PDF bytes (Uint8Array) suitable for download.
 *
 * The output is deterministic for the same (phrase, branding, generatedAt)
 * tuple — so tests can byte-compare. Pass `generatedAt: '<fixed>'` to make
 * the rendered date stable.
 */
export function renderRecoveryPDF({ phrase, appName, generatedAt }: RenderRecoveryOpts): Uint8Array {
  if (!phrase || typeof phrase !== 'string') {
    throw new Error('phrase is required');
  }
  const normalized = normalizePhrase(phrase);
  const words = normalized.split(' ');
  if (words.length !== 24) {
    throw new Error(`expected 24-word account key, got ${words.length} words`);
  }

  const branding = appName
    ? `Account key for your ${appName} account (powered by Tarn).`
    : 'Tarn account key.';
  const dateLine = generatedAt
    ? `Generated: ${generatedAt}`
    : `Generated: ${new Date().toISOString().slice(0, 10)}`;

  const lines: TextRun[] = [
    { y: 730, font: 'F1', size: 24, text: 'Account key' },
    { y: 700, font: 'F2', size: 11, text: branding },
    { y: 684, font: 'F2', size: 11, text: dateLine },

    { y: 640, font: 'F1', size: 13, text: 'Your 24 words:' },
    // Account-key grid (positions filled in below).

    { y: 350, font: 'F1', size: 13, text: 'How to use this kit' },
    { y: 328, font: 'F2', size: 11, text: '1. Print this PDF or save it to a place only you can access (a safe, a' },
    { y: 314, font: 'F2', size: 11, text: '   password manager, an encrypted drive). Anyone with these 24 words' },
    { y: 300, font: 'F2', size: 11, text: '   can recover your account and read everything in it.' },
    { y: 280, font: 'F2', size: 11, text: '2. If you ever lose your password or change devices, enter the words' },
    { y: 266, font: 'F2', size: 11, text: '   at recovery time and pick a new username and password.' },
    { y: 246, font: 'F2', size: 11, text: '3. The order matters. Words must be entered in the same order shown.' },

    { y: 110, font: 'F2', size: 9, text: 'Tarn never stores your account key. This kit was generated entirely' },
    { y: 98, font: 'F2', size: 9, text: 'on your device — these bytes have not been transmitted anywhere.' },
  ];

  // 24 words in a 4-column × 6-row grid below "Your 24 words:".
  // Column x positions: 4 evenly spaced columns starting at MARGIN.
  // Row y positions: top row at 600, decrement 40pt per row → 6 rows.
  const colWidth = (PAGE_W - 2 * MARGIN) / 4;
  for (let i = 0; i < 24; i++) {
    const col = i % 4;
    const row = Math.floor(i / 4);
    const x = MARGIN + col * colWidth + 4;
    const y = 600 - row * 40;
    lines.push({ x, y, font: 'F3', size: 12, text: `${pad2(i + 1)}. ${words[i]!}` });
  }

  return buildSinglePagePDF(lines);
}

function pad2(n: number): string {
  return n < 10 ? ` ${n}` : String(n);
}

/**
 * Minimal single-page PDF generator. Two fonts, one page, content stream of
 * positioned text. PDF reference: PDF 1.4, ISO 32000-1.
 *
 * Object layout (5 indirect objects):
 *   1. Catalog
 *   2. Pages root
 *   3. Page (with Contents reference + font dictionary)
 *   4. Content stream
 *   5/6/7. Helvetica + Helvetica-Bold + Courier (built-in, no embedding)
 */
function buildSinglePagePDF(textRuns: readonly TextRun[]): Uint8Array {
  const stream = textRunsToContentStream(textRuns);
  const streamBytes = new TextEncoder().encode(stream);

  // Object bodies (n.b. each prefixed with "<id> 0 obj\n" and suffixed "\nendobj\n" by writeObj).
  const catalog = '<< /Type /Catalog /Pages 2 0 R >>';
  const pages = '<< /Type /Pages /Kids [3 0 R] /Count 1 >>';
  const page = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ' + PAGE_W + ' ' + PAGE_H + ']'
    + ' /Resources << /Font << /F1 5 0 R /F2 6 0 R /F3 7 0 R >> >>'
    + ' /Contents 4 0 R >>';
  // Note: object 4's body is built inline below (it interleaves the binary
  // stream bytes), so we don't precompute it here.
  const fontHelveticaBold = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>';
  const fontHelvetica = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
  const fontCourier = '<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>';

  // Indices align with the PDF object numbers (1-indexed minus 1).
  // Index 3 is the content-stream object; we handle it specially.
  const objs: string[] = [catalog, pages, page, '', fontHelveticaBold, fontHelvetica, fontCourier];

  // Assemble file.
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  let offset = 0;
  const xref: number[] = [0]; // index 0 is the special free entry

  function push(s: string | Uint8Array): void {
    const b = s instanceof Uint8Array ? s : enc.encode(s);
    parts.push(b);
    offset += b.length;
  }

  push('%PDF-1.4\n');
  // Binary marker comment so naive content-sniffers treat as binary.
  push('%\xff\xff\xff\xff\n');

  for (let i = 0; i < objs.length; i++) {
    xref.push(offset);
    push(`${i + 1} 0 obj\n`);
    if (i === 3) {
      // Object 4 contains the content stream — interleave the binary stream bytes.
      push('<< /Length ' + streamBytes.length + ' >>\nstream\n');
      push(streamBytes);
      push('\nendstream\nendobj\n');
    } else {
      push(objs[i]!);
      push('\nendobj\n');
    }
  }

  const xrefStart = offset;
  push('xref\n');
  push(`0 ${xref.length}\n`);
  push('0000000000 65535 f \n');
  for (let i = 1; i < xref.length; i++) {
    push(`${String(xref[i]).padStart(10, '0')} 00000 n \n`);
  }
  push('trailer\n');
  push(`<< /Size ${xref.length} /Root 1 0 R >>\n`);
  push(`startxref\n${xrefStart}\n`);
  push('%%EOF\n');

  // Concatenate parts into a single Uint8Array.
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const p of parts) {
    out.set(p, cursor);
    cursor += p.length;
  }
  return out;
}

function textRunsToContentStream(runs: readonly TextRun[]): string {
  // Each run is one BT/ET text block. Helvetica/Helvetica-Bold/Courier are
  // built-in PDF fonts, so we don't need to embed glyph data.
  const out: string[] = [];
  for (const r of runs) {
    const x = r.x ?? MARGIN;
    out.push('BT');
    out.push(`/${r.font} ${r.size} Tf`);
    out.push(`${x} ${r.y} Td`);
    out.push(`(${escapePDFString(r.text)}) Tj`);
    out.push('ET');
  }
  return out.join('\n');
}

function escapePDFString(s: string): string {
  // PDF literal strings escape: \ ( ) and non-ASCII via octal. We restrict to
  // ASCII (BIP39 English wordlist + branding strings + ASCII punctuation), so
  // octal escapes aren't required — the strings should round-trip 1:1.
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x28) out += '\\(';
    else if (c === 0x29) out += '\\)';
    else if (c === 0x5c) out += '\\\\';
    else if (c >= 0x20 && c < 0x7f) out += s[i];
    else out += `\\${c.toString(8).padStart(3, '0')}`;
  }
  return out;
}

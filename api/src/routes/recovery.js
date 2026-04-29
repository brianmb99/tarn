// Recovery email forwarder (issue #12).
//
// POST /api/v1/recovery/email
//   Auth: JWT (user)
//   Body: { recipient_email: string, pdf_base64: string, subject?, app_name? }
//   Returns: { ok: true } | error
//
// Forwards a client-rendered recovery PDF to the named recipient via the
// configured email relay (Resend by default — see env.EMAIL_FORWARDER_API_KEY
// / EMAIL_FORWARDER_FROM in wrangler secrets). The PDF is held in memory only
// for the duration of the relay call and then discarded — no D1, no KV, no
// Arweave write. The trust framing is "no storage, brief in-memory visibility
// during forward" (documented in TARN_PROTOCOL.md § Recovery email forwarder).

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';

// Per-account rate limit. Recovery emails are a rare, user-initiated action
// — a bulk-send pattern would either be a client bug or an abuse. 5/hour gives
// reasonable headroom for "send to my work email + my personal email + retry"
// while preventing wallet-draining (the relay charges per send).
const MAX_SENDS_PER_HOUR = 5;

// Maximum allowed PDF size after base64 decode. The renderRecoveryPDF output
// is around 2-3 KB. 200 KB is a generous cap that catches nothing legitimate
// but bounds memory + relay payload size.
const MAX_PDF_BYTES = 200 * 1024;

const RESEND_API_URL = 'https://api.resend.com/emails';

export async function handleRecoveryEmail(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') return errorResponse('Only user accounts can send recovery email', 403, cors);

  // Per-data_lookup_key rate limit. Reuses the write_rate_limits table with a
  // distinct key prefix so it doesn't compete with the data-write budget.
  const hour = new Date().toISOString().slice(0, 13);
  const rateKey = `recovery-email:${auth.data_lookup_key}:${hour}`;
  const expiresAt = Date.now() + 3600_000;
  const rateRow = await env.DB.prepare(`
    INSERT INTO write_rate_limits (key, count, expires_at)
    VALUES (?1, 1, ?2)
    ON CONFLICT(key) DO UPDATE SET count = count + 1
    RETURNING count
  `).bind(rateKey, expiresAt).first();
  if ((rateRow?.count ?? 1) > MAX_SENDS_PER_HOUR) {
    return errorResponse('Recovery email rate limit exceeded', 429, { ...cors, 'Retry-After': '3600' });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { recipient_email, pdf_base64, subject, app_name } = body;

  if (!recipient_email || typeof recipient_email !== 'string') {
    return errorResponse('recipient_email is required', 400, cors);
  }
  // Cheap sanity check — full RFC 5322 validation happens at the relay. Reject
  // anything that doesn't look like user@host so we don't waste a relay call.
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient_email)) {
    return errorResponse('recipient_email is not a valid email address', 400, cors);
  }

  if (!pdf_base64 || typeof pdf_base64 !== 'string') {
    return errorResponse('pdf_base64 is required', 400, cors);
  }
  // Validate base64 + bound size before doing any decoding work.
  if (pdf_base64.length > Math.ceil(MAX_PDF_BYTES * 4 / 3) + 4) {
    return errorResponse(`pdf_base64 exceeds maximum size`, 413, cors);
  }
  let pdfBytes;
  try {
    const bin = atob(pdf_base64);
    pdfBytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) pdfBytes[i] = bin.charCodeAt(i);
  } catch {
    return errorResponse('pdf_base64 is not valid base64', 400, cors);
  }
  if (pdfBytes.length > MAX_PDF_BYTES) {
    return errorResponse('pdf_base64 exceeds maximum size after decode', 413, cors);
  }
  // Sanity-check the magic prefix — Tarn-rendered PDFs start with "%PDF-".
  // We're not protecting against the user uploading a bogus PDF (they've
  // already authenticated), but we want to fail loudly on obvious mistakes
  // like passing a base64-encoded JSON blob.
  if (
    pdfBytes.length < 5 ||
    pdfBytes[0] !== 0x25 || pdfBytes[1] !== 0x50 || pdfBytes[2] !== 0x44 || pdfBytes[3] !== 0x46 || pdfBytes[4] !== 0x2d
  ) {
    return errorResponse('pdf_base64 does not look like a PDF (missing %PDF- header)', 400, cors);
  }

  // Forwarding config. Both vars must be set as Cloudflare secrets:
  //   EMAIL_FORWARDER_API_KEY  - Resend API key (re_...)
  //   EMAIL_FORWARDER_FROM     - "Display Name <verified@your-domain>"
  const apiKey = env.EMAIL_FORWARDER_API_KEY;
  const fromAddress = env.EMAIL_FORWARDER_FROM;
  if (!apiKey || !fromAddress) {
    console.error('[tarn-api] Recovery email forwarder not configured (EMAIL_FORWARDER_API_KEY / EMAIL_FORWARDER_FROM)');
    return errorResponse('Email forwarder not configured', 503, cors);
  }

  const safeAppName = typeof app_name === 'string' && app_name.length > 0 && app_name.length <= 64
    ? app_name
    : 'Tarn';
  const finalSubject = typeof subject === 'string' && subject.length > 0 && subject.length <= 200
    ? subject
    : `Your ${safeAppName} recovery kit`;

  const filename = `${safeAppName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-recovery-kit.pdf`;
  const html = renderEmailBody(safeAppName);

  let relayRes;
  try {
    relayRes = await fetch(RESEND_API_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: fromAddress,
        to: [recipient_email],
        subject: finalSubject,
        html,
        attachments: [{ filename, content: pdf_base64 }],
      }),
    });
  } catch (err) {
    console.error('[tarn-api] Recovery email forwarder error:', err.message);
    return errorResponse('Email relay request failed', 502, cors);
  }

  if (!relayRes.ok) {
    const text = await relayRes.text().catch(() => '');
    console.error(`[tarn-api] Recovery email forwarder ${relayRes.status}: ${text.slice(0, 200)}`);
    return errorResponse(`Email relay rejected request (${relayRes.status})`, 502, cors);
  }

  // Drain + discard. We do not store any field of the response.
  try { await relayRes.body?.cancel(); } catch {}

  return jsonResponse({ ok: true }, 200, cors);
}

function renderEmailBody(appName) {
  // Plain HTML email body — keep it short, no tracking pixels, no images.
  // Most of the user-visible content lives in the PDF attachment.
  const escaped = appName.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  return `<!doctype html>
<html><body style="font-family: system-ui, -apple-system, Helvetica, Arial, sans-serif; color: #222; line-height: 1.5; max-width: 560px; margin: 24px auto; padding: 0 16px;">
<h2 style="margin: 0 0 16px 0;">Your ${escaped} recovery kit</h2>
<p>The PDF attached to this email contains your 24-word recovery phrase. Anyone who has these words can recover your ${escaped} account, so treat them like a key to a safe.</p>
<p><strong>What to do now:</strong></p>
<ol>
<li>Save the attachment to a place only you can access — a password manager, an encrypted drive, or print and store somewhere physical.</li>
<li><strong>Delete this email</strong> once you've saved the attachment. Email inboxes are a common attack target.</li>
</ol>
<p style="color: #888; font-size: 13px; margin-top: 32px;">${escaped} uses Tarn for account recovery. Tarn never stores your recovery phrase or this PDF.</p>
</body></html>`;
}

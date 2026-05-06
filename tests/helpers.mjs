// Shared test helpers — app seeding, user registration, assertions

const DEFAULT_APP_ID = 'test-app';

export { DEFAULT_APP_ID };

/**
 * Seed a test app into D1 via wrangler d1 execute.
 * Call once before running tests that need app registration.
 *
 * Section 8: optional `inviteUrlTemplate` is stored on the app row so
 * invite-token tests can read it back through the public template endpoint.
 */
export async function seedTestApp(appId = DEFAULT_APP_ID, opts = {}) {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  );

  const der = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const pubBase64 = btoa(String.fromCharCode(...new Uint8Array(der)));

  const tpl = typeof opts.inviteUrlTemplate === 'string' ? opts.inviteUrlTemplate : null;
  try {
    const { execSync } = await import('child_process');
    const tplFragment = tpl ? `'${tpl.replace(/'/g, "''")}'` : 'NULL';
    const sql = `INSERT OR REPLACE INTO apps (app_id, public_key, created_at, invite_url_template) VALUES ('${appId}', '${pubBase64}', ${Date.now()}, ${tplFragment})`;
    execSync(
      `npx wrangler d1 execute tarn-api --local --command "${sql}"`,
      { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: 'pipe', timeout: 15000 }
    );
    return { keyPair, pubBase64 };
  } catch (err) {
    console.error(`Failed to seed app '${appId}':`, err.message);
    throw err;
  }
}

/**
 * Mutate an existing invite row's `expires_at` (Section 8). Used by the
 * integration test to backdate a freshly-created invite into the expired
 * window without waiting real wall-clock time.
 */
export async function backdateInviteExpiresAt(tokenId, newExpiresAtSeconds) {
  const { execSync } = await import('child_process');
  const sql = `UPDATE invites SET expires_at = ${newExpiresAtSeconds} WHERE token_id = '${tokenId}'`;
  execSync(
    `npx wrangler d1 execute tarn-api --local --command "${sql}"`,
    { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: 'pipe', timeout: 15000 }
  );
}

export function randomEmail() {
  return `test-${Date.now()}-${Math.random().toString(36).slice(2)}@test.com`;
}

// Alias — tests written after the email→username vocabulary shift import this name.
export const randomUsername = randomEmail;

export async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

/**
 * Force `rules_json='[]'` (== ALLOW) on a freshly-registered account in the
 * local D1 so the test can exercise data writes without involving an app
 * JWT. The production path is `app sets rules via PUT /accounts/:dlk/rules`,
 * but seeding rules directly is the standard pattern in test-e2e and avoids
 * teaching the test about app authentication.
 *
 * @param {string} dataLookupKey - 64-char hex from register's response
 */
export async function forceAllowRulesForAccount(dataLookupKey) {
  const { execSync } = await import('child_process');
  const sql = `UPDATE accounts SET rules_json = '[]' WHERE data_lookup_key = '${dataLookupKey}'`;
  execSync(
    `npx wrangler d1 execute tarn-api --local --command "${sql}"`,
    { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: 'pipe', timeout: 15000 },
  );
}

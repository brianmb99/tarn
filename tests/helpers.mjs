// Shared test helpers — app seeding, user registration, assertions

const DEFAULT_APP_ID = 'test-app';

export { DEFAULT_APP_ID };

/**
 * Seed a test app into D1 via wrangler d1 execute.
 * Call once before running tests that need app registration.
 */
export async function seedTestApp(appId = DEFAULT_APP_ID) {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  );

  const der = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const pubBase64 = btoa(String.fromCharCode(...new Uint8Array(der)));

  try {
    const { execSync } = await import('child_process');
    const sql = `INSERT OR REPLACE INTO apps (app_id, public_key, created_at) VALUES ('${appId}', '${pubBase64}', ${Date.now()})`;
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

export function randomEmail() {
  return `test-${Date.now()}-${Math.random().toString(36).slice(2)}@test.com`;
}

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

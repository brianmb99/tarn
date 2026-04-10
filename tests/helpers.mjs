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
      `npx wrangler d1 execute tarn-api-cache --local --command "${sql}"`,
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

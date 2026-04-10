#!/usr/bin/env node
// Smoke test for Tarn API
// Usage: node test.mjs [baseUrl]
// Default baseUrl: http://localhost:8787

const BASE = process.argv[2] || 'http://localhost:8787';
let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ✗ ${name}: ${err.message}`);
    failed++;
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'Assertion failed');
}

async function fetchJSON(path) {
  const res = await fetch(`${BASE}${path}`);
  const body = await res.json();
  return { status: res.status, body, headers: res.headers };
}

console.log(`\nTarn API Smoke Tests — ${BASE}\n`);

// ============ Health ============
console.log('Health & Info:');

await test('GET /api/v1/health returns 200 or 503 with checks', async () => {
  const { status, body } = await fetchJSON('/api/v1/health');
  assert(status === 200 || status === 503, `unexpected status ${status}`);
  assert(typeof body.healthy === 'boolean', 'missing healthy field');
  assert(body.checks?.d1, 'missing d1 check');
  assert(body.checks?.arweave, 'missing arweave check');
});

await test('GET /api/v1/fees returns fee schedule', async () => {
  const { status, body } = await fetchJSON('/api/v1/fees');
  assert(status === 200, `status ${status}`);
  assert(body.fee === '4700000000000', `wrong fee: ${body.fee}`);
  assert(body.chainId === 8453, 'wrong chainId');
  assert(body.feeVersion === 3, 'wrong feeVersion');
});

// ============ Entries ============
console.log('\nEntries:');

await test('GET /api/v1/entries requires app, type, addr params', async () => {
  const { status, body } = await fetchJSON('/api/v1/entries');
  assert(status === 400, `expected 400, got ${status}`);
  assert(body.error.includes('Missing'), `unexpected error: ${body.error}`);
});

await test('GET /api/v1/entries with params returns entries array', async () => {
  const { status, body } = await fetchJSON('/api/v1/entries?app=bookish&type=entry&addr=0x0000000000000000000000000000000000000000');
  assert(status === 200, `status ${status}`);
  assert(Array.isArray(body.entries), 'entries is not array');
  assert(body.pagination, 'missing pagination');
  assert(body.cache, 'missing cache status');
});

await test('GET /api/v1/entries/:txid returns 404 for non-existent', async () => {
  const { status, body } = await fetchJSON('/api/v1/entries/nonexistenttxid123');
  assert(status === 404, `expected 404, got ${status}`);
});

// ============ Lookup ============
console.log('\nLookup:');

await test('GET /api/v1/lookup requires app, type, key params', async () => {
  const { status, body } = await fetchJSON('/api/v1/lookup');
  assert(status === 400, `expected 400, got ${status}`);
});

await test('GET /api/v1/lookup validates key format', async () => {
  const { status, body } = await fetchJSON('/api/v1/lookup?app=bookish&type=cred&key=tooshort');
  assert(status === 400, `expected 400, got ${status}`);
  assert(body.error.includes('hex'), `unexpected error: ${body.error}`);
});

await test('GET /api/v1/lookup returns 404 for unknown key', async () => {
  const key = '0'.repeat(64);
  const { status } = await fetchJSON(`/api/v1/lookup?app=bookish&type=cred&key=${key}`);
  assert(status === 404, `expected 404, got ${status}`);
});

// ============ CORS ============
console.log('\nCORS:');

await test('OPTIONS returns 204 with CORS headers', async () => {
  const res = await fetch(`${BASE}/api/v1/health`, {
    method: 'OPTIONS',
    headers: {
      'Origin': 'https://getbookish.app',
      'Access-Control-Request-Method': 'GET',
    },
  });
  assert(res.status === 204, `expected 204, got ${res.status}`);
  assert(res.headers.get('access-control-allow-origin'), 'missing CORS origin');
  assert(res.headers.get('access-control-allow-methods'), 'missing CORS methods');
});

await test('POST to read-only endpoint returns 404', async () => {
  const res = await fetch(`${BASE}/api/v1/health`, { method: 'POST' });
  assert(res.status === 404, `expected 404, got ${res.status}`);
});

// ============ Auth ============
console.log('\nAuth:');

await test('POST /auth/challenge returns nonce and message', async () => {
  const res = await fetch(`${BASE}/api/v1/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address: '0x' + '1'.repeat(40) }),
  });
  assert(res.status === 200, `status ${res.status}`);
  const body = await res.json();
  assert(body.nonce && body.nonce.length === 64, 'nonce should be 64-char hex');
  assert(body.message && body.message.includes('Tarn API'), 'message should mention Tarn API');
  assert(body.expiresIn === 300, `expiresIn: ${body.expiresIn}`);
});

await test('POST /auth/challenge rejects invalid address', async () => {
  const res = await fetch(`${BASE}/api/v1/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address: 'not-an-address' }),
  });
  assert(res.status === 400, `status ${res.status}`);
});

await test('POST /auth/verify rejects bad nonce', async () => {
  const res = await fetch(`${BASE}/api/v1/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      address: '0x' + '1'.repeat(40),
      nonce: 'nonexistentnonce',
      signature: '0x' + '0'.repeat(130),
    }),
  });
  assert(res.status === 401, `status ${res.status}`);
});

// ============ Write Auth Guard ============
console.log('\nWrite Auth Guard:');

await test('POST /entries without auth returns 401', async () => {
  const res = await fetch(`${BASE}/api/v1/entries`, {
    method: 'POST',
    body: new Uint8Array([1, 2, 3]),
  });
  assert(res.status === 401, `expected 401, got ${res.status}`);
});

await test('PUT /entries/:id without auth returns 401', async () => {
  const res = await fetch(`${BASE}/api/v1/entries/sometxid`, { method: 'PUT' });
  assert(res.status === 401, `expected 401, got ${res.status}`);
});

await test('DELETE /entries/:id without auth returns 401', async () => {
  const res = await fetch(`${BASE}/api/v1/entries/sometxid`, { method: 'DELETE' });
  assert(res.status === 401, `expected 401, got ${res.status}`);
});

// ============ Sync ============
console.log('\nSync:');

await test('GET /sync/status requires addr param', async () => {
  const { status } = await fetchJSON('/api/v1/sync/status');
  assert(status === 400, `expected 400, got ${status}`);
});

await test('GET /sync/status returns empty for unknown address', async () => {
  const { status, body } = await fetchJSON('/api/v1/sync/status?addr=0x' + '0'.repeat(40));
  assert(status === 200, `status ${status}`);
  assert(body.dirty === false, 'should not be dirty');
  assert(Array.isArray(body.pendingTxids), 'pendingTxids not array');
  assert(body.count === 0, `count: ${body.count}`);
});

await test('POST /sync/ack without auth returns 401', async () => {
  const res = await fetch(`${BASE}/api/v1/sync/ack`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ txids: ['test'] }),
  });
  assert(res.status === 401, `expected 401, got ${res.status}`);
});

// ============ Not Found ============
console.log('\nRouting:');

await test('Unknown path returns 404', async () => {
  const { status } = await fetchJSON('/api/v1/unknown');
  assert(status === 404, `expected 404, got ${status}`);
});

await test('Root path returns 404', async () => {
  const { status } = await fetchJSON('/');
  assert(status === 404, `expected 404, got ${status}`);
});

// ============ Summary ============
console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);

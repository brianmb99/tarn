/**
 * TarnClient + namespaces unit tests. Uses a stub underlying client (no live
 * Tarn API) — verifies wiring, the dynamic collection namespace, lifecycle
 * delegation, and session persistence behavior.
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { defineSchema, TarnClient, TarnStorage } from '../src/index.js';
import type { CollectionDef } from '../src/index.js';
import type { IUnderlyingClient } from '../src/client/index.js';
import type { DecryptedEntry, ShareConnection, Tag, UnderlyingConnection } from '../src/collections/index.js';

// ============ Stub underlying client ============
//
// Implements every method TarnClient or its namespaces touch. Records call
// counts so tests can verify wiring without depending on behavior beyond
// "the call passed through with the right args."

class StubUnderlying implements IUnderlyingClient {
  // State.
  loggedIn = false;
  serializedBlob: string | null = null;

  // Call counters.
  registerCalls = 0;
  loginCalls = 0;
  recoverCalls = 0;
  changeCredentialsCalls = 0;
  deleteAccountCalls = 0;
  clearSessionCalls = 0;
  serializeSessionCalls = 0;
  listSessionsCalls = 0;
  revokeSessionCalls: string[] = [];
  revokeAllSessionsCalls = 0;
  revokeOtherSessionsCalls = 0;
  listConnectionsCalls = 0;
  setConnectionLabelCalls = 0;
  muteCalls = 0;
  unmuteCalls = 0;
  isMutedCalls = 0;
  removeConnectionCalls = 0;
  sendConnectionRequestCalls = 0;
  acceptConnectionRequestCalls = 0;
  listIncomingRequestsCalls = 0;
  createInviteTokenCalls = 0;
  redeemInviteTokenCalls = 0;
  regenerateRecoveryKitCalls = 0;

  entries: DecryptedEntry[] = [];
  shareKeyByTxid = new Map<string, string>();
  blobsByTxid = new Map<string, Uint8Array>();
  shareLogStateByConnection = new Map<string, Record<string, { tx_id: string; cek: string }>>();
  connections: UnderlyingConnection[] = [];
  mutedSharePubs = new Set<string>();
  #txidCounter = 0;
  #shareKeyCounter = 0;

  // ---- Auth ----
  async register(_email: string, _password: string, _opts?: Record<string, unknown>) {
    this.registerCalls++;
    this.loggedIn = true;
    return { ok: true };
  }
  async login(_email: string, _password: string, _opts?: Record<string, unknown>) {
    this.loginCalls++;
    this.loggedIn = true;
    return { ok: true };
  }
  async recoverAccount(_args: Record<string, unknown>) {
    this.recoverCalls++;
    this.loggedIn = true;
    return { ok: true };
  }

  // ---- Session ----
  isLoggedIn(): boolean {
    return this.loggedIn;
  }
  async serializeSession(): Promise<string> {
    this.serializeSessionCalls++;
    return JSON.stringify({ session: 'stub-blob', loggedIn: this.loggedIn });
  }
  async clearSession(): Promise<void> {
    this.clearSessionCalls++;
    this.loggedIn = false;
  }
  async listSessions() {
    this.listSessionsCalls++;
    return [];
  }
  async revokeSession(sid: string) {
    this.revokeSessionCalls.push(sid);
    return { ok: true };
  }
  async revokeAllSessions() {
    this.revokeAllSessionsCalls++;
    this.loggedIn = false;
    return { ok: true };
  }
  async revokeOtherSessions() {
    this.revokeOtherSessionsCalls++;
    return { ok: true };
  }

  // ---- Account ----
  async changeCredentials(_e: string, _p: string, _o?: Record<string, unknown>) {
    this.changeCredentialsCalls++;
    return { ok: true };
  }
  async deleteAccount() {
    this.deleteAccountCalls++;
    this.loggedIn = false;
    return { ok: true };
  }

  // ---- Recovery ----
  lastRegenerateOpts: { phrase: string; appName?: string } | null = null;
  async regenerateRecoveryKit(opts: { phrase: string; appName?: string }) {
    this.regenerateRecoveryKitCalls++;
    this.lastRegenerateOpts = opts;
    return {
      phrase: opts.phrase,
      pdfBytes: new Uint8Array([0x25, 0x50, 0x44, 0x46]), // %PDF
    };
  }

  // ---- Connections ----
  async listConnections() {
    this.listConnectionsCalls++;
    return this.connections;
  }
  async setConnectionLabel(_c: { share_pub: string }, _label: string) {
    this.setConnectionLabelCalls++;
    return { ok: true };
  }
  async muteConnection(c: { share_pub: string }) {
    this.muteCalls++;
    this.mutedSharePubs.add(c.share_pub);
    return { ok: true };
  }
  async unmuteConnection(c: { share_pub: string }) {
    this.unmuteCalls++;
    this.mutedSharePubs.delete(c.share_pub);
    return { ok: true };
  }
  async isMuted(c: { share_pub: string }) {
    this.isMutedCalls++;
    return this.mutedSharePubs.has(c.share_pub);
  }
  async removeConnection(_c: { share_pub: string }) {
    this.removeConnectionCalls++;
    return { ok: true };
  }
  async sendConnectionRequest(_email: string) {
    this.sendConnectionRequestCalls++;
    return { ok: true };
  }
  async acceptConnectionRequest(_nonce: string) {
    this.acceptConnectionRequestCalls++;
    return { ok: true };
  }
  // Pre-seeded by tests that exercise the new typed namespace wrappers.
  // Tests can mutate these directly to shape what listIncomingRequests / etc.
  // return without re-stubbing the methods.
  incomingRequests: Array<{
    senderEmail: string;
    senderSharePubBase64Url: string;
    senderSigningPubBase64: string;
    senderAppId: string;
    requestNonce: string;
    timestamp: number;
    message: string | null;
    viaInviteToken?: string | null;
    txid: string;
  }> = [];
  invitePreviewResult: {
    inviter_display_name: string;
    inviter_share_pub_fingerprint: string;
    app_id: string;
    issued_at: number;
    expires_at: number;
  } | null = null;
  issuedInvites: Array<{
    token_id: string;
    display_name: string;
    issued_at: number;
    expires_at: number;
    redeemed_at: number | null;
    redeemer_share_pub_fingerprint: string | null;
  }> = [];
  previewInviteCalls = 0;
  listIssuedInvitesCalls = 0;
  revokeIssuedInviteCalls: string[] = [];

  async listIncomingRequests() {
    this.listIncomingRequestsCalls++;
    return this.incomingRequests.slice();
  }
  async createInviteToken() {
    this.createInviteTokenCalls++;
    return {
      token_id: 'stub-token-id',
      invite_url: 'tarn:invite/stub-token-id#stub-payload-key',
      expires_at: 1714521600,
    };
  }
  async redeemInviteToken(_t: string, _k: string) {
    this.redeemInviteTokenCalls++;
    return { requestNonce: 'stub-nonce', recipientSharePubBase64Url: 'stub-share-pub' };
  }
  async previewInviteToken(_t: string, _k: string) {
    this.previewInviteCalls++;
    return this.invitePreviewResult;
  }
  async listIssuedInvites() {
    this.listIssuedInvitesCalls++;
    return this.issuedInvites.slice();
  }
  async revokeIssuedInvite(tokenId: string) {
    this.revokeIssuedInviteCalls.push(tokenId);
    return { revoked: true };
  }

  // ---- Entry CRUD (Collection<T> path) ----
  async createEntry(type: string, plaintext: Record<string, unknown>, extraTags: Tag[] = []) {
    const txid = this.#nextTxid();
    const shareKey = this.#nextShareKey();
    this.entries.push({
      txid,
      data: { ...plaintext },
      tags: [{ name: 'Type', value: type }, ...extraTags],
    });
    this.shareKeyByTxid.set(txid, shareKey);
    return { txid, shareKey };
  }
  async updateEntry(priorTxid: string, type: string, plaintext: Record<string, unknown>, extraTags: Tag[] = []) {
    this.entries = this.entries.filter((e) => e.txid !== priorTxid);
    const txid = this.#nextTxid();
    const shareKey = this.#nextShareKey();
    this.entries.push({
      txid,
      data: { ...plaintext },
      tags: [{ name: 'Type', value: type }, ...extraTags],
    });
    this.shareKeyByTxid.set(txid, shareKey);
    return { txid, shareKey };
  }
  async deleteEntry(targetTxid: string, _type: string, _extraTags: Tag[] = []) {
    this.entries = this.entries.filter((e) => e.txid !== targetTxid);
    return { txid: this.#nextTxid() };
  }
  async getEntries(type: string): Promise<DecryptedEntry[]> {
    return this.entries.filter((e) => e.tags.some((t) => t.name === 'Type' && t.value === type));
  }
  async getShareKey(txid: string): Promise<string | null> {
    return this.shareKeyByTxid.get(txid) ?? null;
  }
  async fetchBlob(txid: string): Promise<Uint8Array | null> {
    return this.blobsByTxid.get(txid) ?? null;
  }
  async decryptSharedBlob(_blob: Uint8Array, _shareKey: string): Promise<Record<string, unknown>> {
    return { stub: true };
  }
  async shareContent(c: ShareConnection, contentId: string, txid: string, shareKey: string) {
    let state = this.shareLogStateByConnection.get(c.share_pub);
    if (!state) {
      state = {};
      this.shareLogStateByConnection.set(c.share_pub, state);
    }
    state[contentId] = { tx_id: txid, cek: shareKey };
    return { ok: true };
  }
  async unshareContent(c: ShareConnection, contentId: string) {
    const state = this.shareLogStateByConnection.get(c.share_pub);
    if (state) delete state[contentId];
    return { ok: true };
  }
  async readShareLog(c: ShareConnection) {
    return this.shareLogStateByConnection.get(c.share_pub) ?? {};
  }

  // ---- Helpers ----
  #nextTxid(): string {
    this.#txidCounter++;
    return `mock-tx-${this.#txidCounter}`;
  }
  #nextShareKey(): string {
    this.#shareKeyCounter++;
    return `mock-sk-${this.#shareKeyCounter}`;
  }
}

// ============ Schema fixture ============

const schema = defineSchema({
  appId: 'bookish',
  version: 4,
  collections: {
    books: {
      primaryKey: 'bookId',
      fields: {
        bookId: 'string',
        title: 'string',
        rating: 'number?',
        isPrivate: { type: 'boolean', default: false },
      },
      shareable: true,
    },
    settings: {
      primaryKey: 'key',
      fields: { key: 'string', value: 'json' },
      shareable: false,
    },
  },
});

// ============ Helpers ============

function makeClient(stub: StubUnderlying = new StubUnderlying()) {
  return TarnClient.create({
    apiBase: 'https://api.tarn.dev',
    appId: 'bookish',
    schema,
    storage: TarnStorage.memory(),
    underlying: () => stub,
  });
}

// ============ Factory ============

describe('TarnClient.create', () => {
  it('constructs a client with the correct namespaces', async () => {
    const tarn = await makeClient();
    assert.ok(tarn.connections);
    assert.ok(tarn.account);
    assert.ok(tarn.session);
    assert.ok(tarn.recovery);
    assert.ok(tarn.advanced);
    assert.ok(tarn.advanced.entries);
    assert.ok(tarn.advanced.shareLog);
  });

  it('exposes collections as top-level properties', async () => {
    const tarn = await makeClient();
    // tarn.books and tarn.settings should be accessible directly.
    assert.ok((tarn as unknown as { books: unknown }).books);
    assert.ok((tarn as unknown as { settings: unknown }).settings);
  });

  it('rejects schema/appId mismatch', async () => {
    await assert.rejects(
      () => TarnClient.create({
        apiBase: 'https://api.tarn.dev',
        appId: 'mismatch',
        schema,
        storage: TarnStorage.memory(),
        underlying: () => new StubUnderlying(),
      }),
      /schema.appId .* does not match/,
    );
  });

  it('rejects missing required config fields', async () => {
    // `underlying` is optional (defaults to the bundled legacy client) — only
    // apiBase / appId / schema / storage are required.
    const badConfigs = [
      { apiBase: undefined as unknown as string, appId: 'bookish' },
      { apiBase: 'x', appId: undefined as unknown as string },
      { apiBase: 'x', appId: 'bookish', schema: undefined as unknown as never },
      { apiBase: 'x', appId: 'bookish', schema, storage: undefined as unknown as never },
    ];
    for (const cfg of badConfigs) {
      await assert.rejects(() => TarnClient.create(cfg as never), /required/);
    }
  });
});

// ============ Auth + session persistence ============

describe('TarnClient — auth and session persistence', () => {
  let stub: StubUnderlying;
  let storage: ReturnType<typeof TarnStorage.memory>;
  let tarn: Awaited<ReturnType<typeof makeClient>>;

  beforeEach(async () => {
    stub = new StubUnderlying();
    storage = TarnStorage.memory();
    tarn = await TarnClient.create({
      apiBase: 'https://api.tarn.dev',
      appId: 'bookish',
      schema,
      storage,
      underlying: () => stub,
    });
  });

  it('register persists the session to storage', async () => {
    await tarn.register('a@b.c', 'pw');
    assert.equal(stub.registerCalls, 1);
    assert.equal(stub.serializeSessionCalls, 1);
    const blob = await storage.read();
    assert.ok(blob, 'storage should hold a session blob after register');
  });

  it('login persists the session to storage', async () => {
    await tarn.login('a@b.c', 'pw');
    assert.equal(stub.loginCalls, 1);
    const blob = await storage.read();
    assert.ok(blob);
  });

  it('isLoggedIn delegates to the underlying client', async () => {
    assert.equal(tarn.isLoggedIn(), false);
    await tarn.login('a@b.c', 'pw');
    assert.equal(tarn.isLoggedIn(), true);
  });

  it('session.clear() wipes the persisted blob and logs out', async () => {
    await tarn.login('a@b.c', 'pw');
    assert.ok(await storage.read());
    await tarn.session.clear();
    assert.equal(stub.clearSessionCalls, 1);
    assert.equal(await storage.read(), null);
  });

  it('account.delete() wipes the persisted blob and logs out', async () => {
    await tarn.login('a@b.c', 'pw');
    await tarn.account.delete();
    assert.equal(stub.deleteAccountCalls, 1);
    assert.equal(await storage.read(), null);
    assert.equal(tarn.isLoggedIn(), false);
  });

  it('session.revokeAll() wipes the persisted blob', async () => {
    await tarn.login('a@b.c', 'pw');
    await tarn.session.revokeAll();
    assert.equal(stub.revokeAllSessionsCalls, 1);
    assert.equal(await storage.read(), null);
  });
});

// ============ Session resume (Gap C) ============
//
// Drives `resolveUnderlying` directly with mock storage + a stub resumer
// because `TarnClient.create()` invokes the bundled legacy client's
// resumeSession when no `underlying` factory is set, which a unit test
// can't reach without an end-to-end environment. The integration test
// for the real resume path lives in tests/test-session-resume.mjs.

describe('resolveUnderlying — session resume', () => {
  // Lazy-load to avoid pulling the whole client module if these tests are
  // skipped by file-level filters.
  async function loadResolver() {
    const mod = await import('../src/client/tarn-client.js');
    return mod.resolveUnderlying;
  }

  function makeStub(): IUnderlyingClient {
    return new StubUnderlying() as unknown as IUnderlyingClient;
  }

  it('returns fresh client when no blob is persisted', async () => {
    const resolveUnderlying = await loadResolver();
    const storage = TarnStorage.memory();
    const fresh = makeStub();
    let resumeCalls = 0;
    const out = await resolveUnderlying({
      apiBase: 'https://api.tarn.dev',
      appId: 'bookish',
      storage,
      resume: async () => { resumeCalls++; return null; },
      fresh: () => fresh,
    });
    assert.equal(out, fresh);
    assert.equal(resumeCalls, 0, 'resume must not be called without a blob');
  });

  it('returns the resumed client when storage has a valid blob', async () => {
    const resolveUnderlying = await loadResolver();
    const storage = TarnStorage.memory();
    await storage.write('persisted-blob');
    const resumed = makeStub();
    const fresh = makeStub();
    let resumeArgs: [string, string, string] | null = null;
    const out = await resolveUnderlying({
      apiBase: 'https://api.tarn.dev',
      appId: 'bookish',
      storage,
      resume: async (api, app, blob) => {
        resumeArgs = [api, app, blob];
        return resumed;
      },
      fresh: () => fresh,
    });
    assert.equal(out, resumed, 'resumed instance should be used');
    assert.deepEqual(resumeArgs, ['https://api.tarn.dev', 'bookish', 'persisted-blob']);
    // Storage should still hold the blob — successful resume does not clear it.
    assert.equal(await storage.read(), 'persisted-blob');
  });

  it('falls back to fresh and clears storage when resume returns null', async () => {
    const resolveUnderlying = await loadResolver();
    const storage = TarnStorage.memory();
    await storage.write('stale-blob');
    const fresh = makeStub();
    const out = await resolveUnderlying({
      apiBase: 'https://api.tarn.dev',
      appId: 'bookish',
      storage,
      resume: async () => null,
      fresh: () => fresh,
    });
    assert.equal(out, fresh);
    assert.equal(await storage.read(), null, 'stale blob must be cleared');
  });

  it('falls back to fresh and clears storage when resume throws', async () => {
    const resolveUnderlying = await loadResolver();
    const storage = TarnStorage.memory();
    await storage.write('corrupt-blob');
    const fresh = makeStub();
    const out = await resolveUnderlying({
      apiBase: 'https://api.tarn.dev',
      appId: 'bookish',
      storage,
      resume: async () => { throw new Error('decrypt failed'); },
      fresh: () => fresh,
    });
    assert.equal(out, fresh);
    assert.equal(await storage.read(), null);
  });

  it('falls back to fresh when storage.read throws (does not call resume or clear)', async () => {
    const resolveUnderlying = await loadResolver();
    let clearCalls = 0;
    const storage = {
      async read(): Promise<string | null> { throw new Error('quota exceeded'); },
      async write(_: string): Promise<void> {},
      async clear(): Promise<void> { clearCalls++; },
    };
    const fresh = makeStub();
    let resumeCalls = 0;
    const out = await resolveUnderlying({
      apiBase: 'https://api.tarn.dev',
      appId: 'bookish',
      storage,
      resume: async () => { resumeCalls++; return makeStub(); },
      fresh: () => fresh,
    });
    assert.equal(out, fresh);
    assert.equal(resumeCalls, 0, 'resume must not be called when read fails');
    assert.equal(clearCalls, 0, 'clear must not be called — there is no blob to invalidate');
  });

  it('skips resume entirely when resume hook is null (test-factory path)', async () => {
    const resolveUnderlying = await loadResolver();
    const storage = TarnStorage.memory();
    await storage.write('a-blob');
    const fresh = makeStub();
    const out = await resolveUnderlying({
      apiBase: 'https://api.tarn.dev',
      appId: 'bookish',
      storage,
      resume: null,
      fresh: () => fresh,
    });
    assert.equal(out, fresh);
    // Blob untouched — not our place to clear when the caller said "skip".
    assert.equal(await storage.read(), 'a-blob');
  });
});

// ============ Dynamic collection namespace ============

describe('TarnClient — collection namespace', () => {
  it('tarn.books behaves like a Collection (create / list / update / delete)', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    const t = tarn as unknown as {
      books: {
        create(r: { bookId: string; title: string; isPrivate?: boolean }): Promise<unknown>;
        list(): Promise<Array<{ bookId: string; title: string }>>;
        update(id: string, p: { rating?: number }): Promise<unknown>;
        delete(id: string): Promise<void>;
      };
    };

    await t.books.create({ bookId: 'b1', title: 'Foo' });
    await t.books.create({ bookId: 'b2', title: 'Bar' });
    const list = await t.books.list();
    assert.equal(list.length, 2);
    assert.deepEqual(list.map((b) => b.bookId).sort(), ['b1', 'b2']);

    await t.books.update('b1', { rating: 5 });
    const after = await t.books.list();
    assert.equal((after.find((b) => b.bookId === 'b1') as { rating?: number })?.rating, 5);

    await t.books.delete('b2');
    const final = await t.books.list();
    assert.equal(final.length, 1);
    assert.equal(final[0]!.bookId, 'b1');
  });

  it('tarn.settings exists but does not have share methods (shareable: false)', async () => {
    const tarn = await makeClient();
    const t = tarn as unknown as {
      settings: {
        share?: unknown;
        create(r: { key: string; value: unknown }): Promise<unknown>;
      };
    };
    await t.settings.create({ key: 'theme', value: 'dark' });
    // Calling share() throws (the schema lacks shareable).
    await assert.rejects(
      // The Collection class still has share() as a member; it just throws.
      () => (t.settings as unknown as { share: (...args: unknown[]) => Promise<void> }).share(
        { share_pub: 'sp', signing_pub: 'sg' }, 'theme',
      ),
      /requires the collection to declare shareable: true/,
    );
  });
});

// ============ Lifecycle namespaces ============

describe('TarnClient — lifecycle namespaces wire to the underlying client', () => {
  let stub: StubUnderlying;
  let tarn: Awaited<ReturnType<typeof makeClient>>;

  beforeEach(async () => {
    stub = new StubUnderlying();
    tarn = await makeClient(stub);
  });

  it('connections.list normalizes the underlying records', async () => {
    stub.connections = [
      { share_pub: 'sp1', signing_pub: 'sg1', label: 'Alice', muted: false, extra: 'ignored' },
      { share_pub: 'sp2', signing_pub: 'sg2' },
    ];
    const list = await tarn.connections.list();
    assert.equal(list.length, 2);
    assert.equal(list[0]!.label, 'Alice');
    assert.equal(list[0]!.muted, false);
    // 'extra' is intentionally not surfaced — the public Connection type is stable.
    assert.equal((list[0] as unknown as Record<string, unknown>)['extra'], undefined);
    assert.equal(list[1]!.label, undefined);
  });

  it('connections.list surfaces email / established_at / initial_request_nonce', async () => {
    stub.connections = [
      {
        share_pub: 'sp1',
        signing_pub: 'sg1',
        email: 'maya@example.com',
        established_at: 1714521600,
        initial_request_nonce: 'nonce-abc',
        label: 'Maya',
      },
      // Invite-token connection: no email, but still has established_at.
      {
        share_pub: 'sp2',
        signing_pub: 'sg2',
        established_at: 1714525200,
      },
    ];
    const list = await tarn.connections.list();
    assert.equal(list[0]!.email, 'maya@example.com');
    assert.equal(list[0]!.established_at, 1714521600);
    assert.equal(list[0]!.initial_request_nonce, 'nonce-abc');
    assert.equal(list[1]!.email, undefined, 'invite-token connections may lack email');
    assert.equal(list[1]!.established_at, 1714525200);
    assert.equal(list[1]!.initial_request_nonce, undefined);
  });

  it('connections.list omits absent optional fields rather than emitting null', async () => {
    // Some legacy / partial records may carry nulls. Public Connection type
    // is "absent or value", never null — verify we drop nulls cleanly.
    stub.connections = [
      {
        share_pub: 'sp1',
        signing_pub: 'sg1',
        email: null,
        established_at: null,
        initial_request_nonce: null,
      },
    ];
    const list = await tarn.connections.list();
    const c = list[0]!;
    assert.equal(c.email, undefined);
    assert.equal(c.established_at, undefined);
    assert.equal(c.initial_request_nonce, undefined);
    // Stable identifiers always present.
    assert.equal(c.share_pub, 'sp1');
    assert.equal(c.signing_pub, 'sg1');
  });

  it('connections.mute / unmute / isMuted delegate', async () => {
    const c = { share_pub: 'sp1', signing_pub: 'sg1' };
    await tarn.connections.mute(c);
    assert.equal(stub.muteCalls, 1);
    assert.equal(await tarn.connections.isMuted(c), true);
    await tarn.connections.unmute(c);
    assert.equal(stub.unmuteCalls, 1);
    assert.equal(await tarn.connections.isMuted(c), false);
  });

  it('connections.createInvite returns the typed InviteToken shape', async () => {
    const out = await tarn.connections.createInvite({ display_name: 'Alice', expiry_days: 3 });
    assert.equal(stub.createInviteTokenCalls, 1);
    assert.equal(out.token_id, 'stub-token-id');
    assert.equal(out.invite_url, 'tarn:invite/stub-token-id#stub-payload-key');
    assert.equal(out.expires_at, 1714521600);
  });

  it('connections.previewInvite returns null when the underlying does (recoverable failure)', async () => {
    stub.invitePreviewResult = null;
    const out = await tarn.connections.previewInvite('tok', 'key');
    assert.equal(stub.previewInviteCalls, 1);
    assert.equal(out, null);
  });

  it('connections.previewInvite normalizes the underlying preview shape', async () => {
    stub.invitePreviewResult = {
      inviter_display_name: 'Maya',
      inviter_share_pub_fingerprint: '0123abcd',
      app_id: 'bookish',
      issued_at: 1714000000,
      expires_at: 1714600000,
    };
    const out = await tarn.connections.previewInvite('tok', 'key');
    assert.deepEqual(out, {
      inviter_display_name: 'Maya',
      inviter_share_pub_fingerprint: '0123abcd',
      app_id: 'bookish',
      issued_at: 1714000000,
      expires_at: 1714600000,
    });
  });

  it('connections.redeemInvite renames camelCase fields to snake_case', async () => {
    const out = await tarn.connections.redeemInvite('tok', 'key');
    assert.equal(out.request_nonce, 'stub-nonce');
    assert.equal(out.recipient_share_pub, 'stub-share-pub');
    // Verify we don't leak the underlying camelCase keys.
    const o = out as unknown as Record<string, unknown>;
    assert.equal(o['requestNonce'], undefined);
    assert.equal(o['recipientSharePubBase64Url'], undefined);
  });

  it('connections.listIssuedInvites returns IssuedInvite[]', async () => {
    stub.issuedInvites = [
      {
        token_id: 't1',
        display_name: 'For Bob',
        issued_at: 1714000000,
        expires_at: 1714600000,
        redeemed_at: null,
        redeemer_share_pub_fingerprint: null,
      },
      {
        token_id: 't2',
        display_name: 'For Maya',
        issued_at: 1714100000,
        expires_at: 1714700000,
        redeemed_at: 1714200000,
        redeemer_share_pub_fingerprint: 'abcd',
      },
    ];
    const list = await tarn.connections.listIssuedInvites();
    assert.equal(stub.listIssuedInvitesCalls, 1);
    assert.equal(list.length, 2);
    assert.equal(list[0]!.token_id, 't1');
    assert.equal(list[0]!.redeemed_at, null);
    assert.equal(list[1]!.redeemed_at, 1714200000);
    assert.equal(list[1]!.redeemer_share_pub_fingerprint, 'abcd');
  });

  it('connections.revokeIssuedInvite passes the tokenId through', async () => {
    const out = await tarn.connections.revokeIssuedInvite('tok-to-revoke');
    assert.deepEqual(stub.revokeIssuedInviteCalls, ['tok-to-revoke']);
    assert.equal(out.revoked, true);
  });

  it('connections.listIncomingRequests normalizes camelCase → snake_case', async () => {
    stub.incomingRequests = [
      {
        senderEmail: 'alice@example.com',
        senderSharePubBase64Url: 'sp-alice',
        senderSigningPubBase64: 'sg-alice',
        senderAppId: 'bookish',
        requestNonce: 'nonce-1',
        timestamp: 1714000000,
        message: null,
        viaInviteToken: 'inv-token-1',
        txid: 'tx-1',
      },
      {
        // No viaInviteToken — direct email handshake.
        senderEmail: 'bob@example.com',
        senderSharePubBase64Url: 'sp-bob',
        senderSigningPubBase64: 'sg-bob',
        senderAppId: 'bookish',
        requestNonce: 'nonce-2',
        timestamp: 1714000100,
        message: 'hi',
        txid: 'tx-2',
      },
    ];
    const list = await tarn.connections.listIncomingRequests();
    assert.equal(list.length, 2);
    assert.equal(list[0]!.email, 'alice@example.com');
    assert.equal(list[0]!.share_pub, 'sp-alice');
    assert.equal(list[0]!.signing_pub, 'sg-alice');
    assert.equal(list[0]!.app_id, 'bookish');
    assert.equal(list[0]!.request_nonce, 'nonce-1');
    assert.equal(list[0]!.via_invite_token, 'inv-token-1');
    assert.equal(list[1]!.via_invite_token, undefined);
    assert.equal(list[1]!.message, 'hi');
  });

  it('connections.listIncomingRequests passes opts to the underlying', async () => {
    let received: Record<string, unknown> | undefined;
    stub.listIncomingRequests = async (opts?: Record<string, unknown>) => {
      stub.listIncomingRequestsCalls++;
      received = opts;
      return [];
    };
    await tarn.connections.listIncomingRequests({ windows: 5 });
    assert.deepEqual(received, { windows: 5 });
  });

  it('account.changeCredentials delegates', async () => {
    await tarn.account.changeCredentials('new@e.com', 'newpw');
    assert.equal(stub.changeCredentialsCalls, 1);
  });

  it('recovery.export({ format: pdf }) returns the PDF bytes and forwards the phrase', async () => {
    const phrase = 'one two three four five six seven eight nine ten eleven twelve';
    const result = await tarn.recovery.export({ format: 'pdf', phrase });
    assert.ok(result instanceof Uint8Array);
    assert.equal(stub.regenerateRecoveryKitCalls, 1);
    assert.equal(stub.lastRegenerateOpts?.phrase, phrase, 'must pass phrase through to underlying');
  });

  it('recovery.export({ format: json }) returns the structured kit', async () => {
    const phrase = 'one two three four five six seven eight nine ten eleven twelve';
    const result = await tarn.recovery.export({ format: 'json', phrase, appName: 'Bookish' });
    assert.ok(!(result instanceof Uint8Array));
    const json = result as { phrase: string; appName: string; generatedAt: string };
    assert.equal(json.phrase, phrase);
    assert.equal(json.appName, 'Bookish');
    assert.ok(json.generatedAt);
  });

  it('session.listDevices delegates', async () => {
    await tarn.session.listDevices();
    assert.equal(stub.listSessionsCalls, 1);
  });

  it('session.revokeDevice delegates with sid', async () => {
    await tarn.session.revokeDevice('sid-123');
    assert.deepEqual(stub.revokeSessionCalls, ['sid-123']);
  });
});

// ============ Advanced namespace ============

describe('TarnClient.advanced', () => {
  it('advanced.entries.create delegates to underlying createEntry', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    const result = await tarn.advanced.entries.create('bookish-custom', { foo: 'bar' });
    assert.equal(stub.entries.length, 1);
    assert.equal(stub.entries[0]!.data['foo'], 'bar');
    assert.equal(result.txid, 'mock-tx-1');
    assert.equal(result.shareKey, 'mock-sk-1');
  });

  it('advanced.entries.fetchBlob delegates', async () => {
    const stub = new StubUnderlying();
    stub.blobsByTxid.set('tx1', new Uint8Array([42]));
    const tarn = await makeClient(stub);
    const blob = await tarn.advanced.entries.fetchBlob('tx1');
    assert.ok(blob);
    assert.equal(blob[0], 42);
  });

  it('advanced.shareLog.read returns the connection state map', async () => {
    const stub = new StubUnderlying();
    stub.shareLogStateByConnection.set('sp1', {
      'books:b1': { tx_id: 'tx1', cek: 'sk1' },
    });
    const tarn = await makeClient(stub);
    const state = await tarn.advanced.shareLog.read({ share_pub: 'sp1', signing_pub: 'sg1' });
    assert.ok(state['books:b1']);
    assert.equal(state['books:b1'].tx_id, 'tx1');
  });
});

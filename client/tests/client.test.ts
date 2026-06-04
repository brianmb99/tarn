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
import { deriveEid } from '../src/collections/eid.js';

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

  entries: DecryptedEntry[] = [];
  shareKeyByTxid = new Map<string, string>();
  blobsByTxid = new Map<string, Uint8Array>();
  shareLogStateByConnection = new Map<string, Record<string, { tx_id: string; cek: string }>>();
  connections: UnderlyingConnection[] = [];
  mutedSharePubs = new Set<string>();
  #txidCounter = 0;
  #shareKeyCounter = 0;

  // ---- Auth ----
  async register(_username: string, _password: string, _opts?: Record<string, unknown>) {
    this.registerCalls++;
    this.loggedIn = true;
    return { ok: true };
  }
  async login(_username: string, _password: string, _opts?: Record<string, unknown>) {
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

  // ---- Account-key (Phase 3 + Phase 4) ----
  viewAccountKeyCalls = 0;
  viewAccountKeyResult: { accountKey: string } = { accountKey: 'stub-phrase' };
  accountKeyStored: boolean | null = null;
  enableKeyStorageCalls = 0;
  disableKeyStorageCalls = 0;
  rotateAccountKeyCalls = 0;
  rotateAccountKeyResult: { accountKey: string } = { accountKey: 'rotated-stub-phrase' };
  async viewAccountKey(_opts: { password: string }) {
    this.viewAccountKeyCalls++;
    return this.viewAccountKeyResult;
  }
  async enableKeyStorage(_opts: { password: string; accountKey: string }) {
    this.enableKeyStorageCalls++;
    this.accountKeyStored = true;
    return { stored: true as const };
  }
  async disableKeyStorage(_opts: { password: string }) {
    this.disableKeyStorageCalls++;
    this.accountKeyStored = false;
    return { stored: false as const };
  }
  async rotateAccountKey(_opts: { password: string }) {
    this.rotateAccountKeyCalls++;
    return this.rotateAccountKeyResult;
  }
  isAccountKeyStored(): boolean | null {
    return this.accountKeyStored;
  }

  // ---- Passkeys (Phase 6) ----
  passkeysSupportedResult = false;
  registerPasskeyCalls = 0;
  authenticateWithPasskeyCalls = 0;
  listPasskeysResult: Array<{
    credentialId: string;
    deviceLabel: string | null;
    createdAt: number;
    lastUsedAt: number | null;
    stale: boolean;
  }> = [];
  removePasskeyCalls = 0;
  async passkeysSupported() { return this.passkeysSupportedResult; }
  async registerPasskey(_opts?: { deviceLabel?: string }) {
    this.registerPasskeyCalls++;
    return { credentialId: 'stub-cred-id', deviceLabel: _opts?.deviceLabel ?? null };
  }
  async authenticateWithPasskey(_opts?: { deviceLabel?: string; credentialId?: string }) {
    this.authenticateWithPasskeyCalls++;
    return { dataLookupKey: 'stub-dlk' };
  }
  async listPasskeys() { return this.listPasskeysResult.slice(); }
  async removePasskey(_opts: { credentialId: string; password: string }) {
    this.removePasskeyCalls++;
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
  async sendConnectionRequest(_username: string) {
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
    senderUsername: string;
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
    inviter_share_pub_fingerprint: string;
    app_id: string;
    issued_at: number;
    expires_at: number;
  } | null = null;
  issuedInvites: Array<{
    token_id: string;
    label: string;
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
  // Records the most recent batchCreate args so tests can assert
  // forwarding fidelity without re-stubbing the method.
  batchCreateCalls: Array<{ type: string; items: Array<Record<string, unknown>>; extraTagsPerItem: Tag[][] }> = [];
  async batchCreate(
    type: string,
    items: Array<Record<string, unknown>>,
    extraTagsPerItem: Tag[][] = [],
  ) {
    this.batchCreateCalls.push({
      type,
      items: items.slice(),
      extraTagsPerItem: extraTagsPerItem.map((t) => t.slice()),
    });
    const out: Array<{ txid: string; shareKey: string | null }> = [];
    for (let i = 0; i < items.length; i++) {
      const item = items[i]!;
      const perItem = extraTagsPerItem[i] ?? [];
      const txid = this.#nextTxid();
      const shareKey = this.#nextShareKey();
      this.entries.push({
        txid,
        data: { ...item },
        tags: [{ name: 'Type', value: type }, ...perItem],
      });
      this.shareKeyByTxid.set(txid, shareKey);
      out.push({ txid, shareKey });
    }
    return out;
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
  async getEntryByEid(type: string, eid: string): Promise<DecryptedEntry | null> {
    return this.entries.find((e) =>
      e.tags.some((t) => t.name === 'Type' && t.value === type) &&
      e.tags.some((t) => t.name === 'Eid' && t.value === eid),
    ) ?? null;
  }
  async getEntriesSince(_type: string): Promise<{
    entries: Array<{ eid: string | null; txid: string; data: Record<string, unknown>; tags: Tag[] }>;
    deleted: string[];
  }> {
    return { entries: [], deleted: [] };
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
    assert.ok(tarn.accountKey);
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

  it('connections.list surfaces username / established_at / initial_request_nonce', async () => {
    stub.connections = [
      {
        share_pub: 'sp1',
        signing_pub: 'sg1',
        username: 'maya@example.com',
        established_at: 1714521600,
        initial_request_nonce: 'nonce-abc',
        label: 'Maya',
      },
      // Invite-token connection: no username, but still has established_at.
      {
        share_pub: 'sp2',
        signing_pub: 'sg2',
        established_at: 1714525200,
      },
    ];
    const list = await tarn.connections.list();
    assert.equal(list[0]!.username, 'maya@example.com');
    assert.equal(list[0]!.established_at, 1714521600);
    assert.equal(list[0]!.initial_request_nonce, 'nonce-abc');
    assert.equal(list[1]!.username, undefined, 'invite-token connections may lack username');
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
        username: null,
        established_at: null,
        initial_request_nonce: null,
      },
    ];
    const list = await tarn.connections.list();
    const c = list[0]!;
    assert.equal(c.username, undefined);
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
    const out = await tarn.connections.createInvite({ label: 'Alice', expiry_days: 3 });
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
      inviter_share_pub_fingerprint: '0123abcd',
      app_id: 'bookish',
      issued_at: 1714000000,
      expires_at: 1714600000,
    };
    const out = await tarn.connections.previewInvite('tok', 'key');
    assert.deepEqual(out, {
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
        label: 'For Bob',
        issued_at: 1714000000,
        expires_at: 1714600000,
        redeemed_at: null,
        redeemer_share_pub_fingerprint: null,
      },
      {
        token_id: 't2',
        label: 'For Maya',
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
        senderUsername: 'alice@example.com',
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
        // No viaInviteToken — direct username handshake.
        senderUsername: 'bob@example.com',
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
    assert.equal(list[0]!.username, 'alice@example.com');
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

  it('advanced.entries.batchCreate is exposed on the namespace', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    assert.equal(typeof tarn.advanced.entries.batchCreate, 'function');
  });

  it('advanced.entries.getEntriesSince is exposed on the namespace', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    assert.equal(typeof tarn.advanced.entries.getEntriesSince, 'function');
    // Smoke: calling it routes through the stub, returns the empty-default shape.
    const result = await tarn.advanced.entries.getEntriesSince('any-type');
    assert.deepEqual(result, { entries: [], deleted: [] });
  });

  it('advanced.entries.batchCreate forwards (type, items, extraTags) to underlying as per-item tags', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    // Use a schema-less type so no Eid auto-stamping happens — keeps the
    // assertion focused on the batch-level extraTags → per-item forwarding.
    const items = [{ a: 1 }, { a: 2 }, { a: 3 }];
    const extraTags: Tag[] = [{ name: 'Custom', value: 'X' }];
    const out = await tarn.advanced.entries.batchCreate('bookish-custom', items, extraTags);
    assert.equal(stub.batchCreateCalls.length, 1);
    assert.equal(stub.batchCreateCalls[0]!.type, 'bookish-custom');
    assert.deepEqual(stub.batchCreateCalls[0]!.items, items);
    // Legacy batch-level extraTags applied to every item.
    assert.deepEqual(stub.batchCreateCalls[0]!.extraTagsPerItem, [extraTags, extraTags, extraTags]);
    assert.equal(out.length, 3);
    assert.deepEqual(out.map((r) => r.txid), ['mock-tx-1', 'mock-tx-2', 'mock-tx-3']);
    assert.deepEqual(out.map((r) => r.shareKey), ['mock-sk-1', 'mock-sk-2', 'mock-sk-3']);
  });

  it('advanced.entries.batchCreate auto-stamps Eid + SchemaV when type matches a defined collection', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    const items = [
      { bookId: 'b1', title: 'A', isPrivate: false },
      { bookId: 'b2', title: 'B', isPrivate: false },
    ];
    await tarn.advanced.entries.batchCreate('books', items);
    assert.equal(stub.batchCreateCalls.length, 1);
    const tagsPerItem = stub.batchCreateCalls[0]!.extraTagsPerItem;
    assert.equal(tagsPerItem.length, 2);
    // Each item must carry an Eid tag (auto-stamped from primaryKey)
    // and a SchemaV tag (from the collection's schema version).
    for (const tags of tagsPerItem) {
      assert.ok(tags.find((t) => t.name === 'Eid')?.value, 'Eid tag must be stamped');
      assert.ok(tags.find((t) => t.name === 'SchemaV')?.value, 'SchemaV tag must be stamped');
    }
    // The Eids must differ — they're derived per primaryKey.
    const eid1 = tagsPerItem[0]!.find((t) => t.name === 'Eid')!.value;
    const eid2 = tagsPerItem[1]!.find((t) => t.name === 'Eid')!.value;
    assert.notEqual(eid1, eid2, 'Eids must differ per primaryKey');
  });

  it('advanced.entries.batchCreate throws when a typed-collection item is missing primaryKey', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    // 'books' has primaryKey: 'bookId' — second item is missing it.
    const items = [{ bookId: 'b1', title: 'A', isPrivate: false }, { title: 'no-pk' }];
    await assert.rejects(
      () => tarn.advanced.entries.batchCreate('books', items),
      // Schema validation surfaces the missing required primaryKey as the
      // standard "required field 'X' is missing" message from
      // validateRecordForCreate, prefixed with the failing input index.
      /\[1\] .*required field 'bookId' is missing/,
    );
    // Nothing got forwarded — the throw happens before the wire call.
    assert.equal(stub.batchCreateCalls.length, 0);
  });

  it('advanced.entries.batchCreate preserves input order in the returned array', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    const items = [{ marker: 'first' }, { marker: 'second' }, { marker: 'third' }];
    const out = await tarn.advanced.entries.batchCreate('order-test', items);
    // Verify result order matches input order (not e.g. alphabetic on txid).
    const dataOrder = out.map((r) => {
      const entry = stub.entries.find((e) => e.txid === r.txid)!;
      return entry.data['marker'];
    });
    assert.deepEqual(dataOrder, ['first', 'second', 'third']);
  });

  it('advanced.entries.batchCreate throws on empty input', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    await assert.rejects(
      () => tarn.advanced.entries.batchCreate('t', []),
      /non-empty/i,
    );
    assert.equal(stub.batchCreateCalls.length, 0, 'underlying not called on bad input');
  });

  it('advanced.entries.batchCreate throws on 26+ items', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    const items = Array.from({ length: 26 }, (_, i) => ({ i }));
    await assert.rejects(
      () => tarn.advanced.entries.batchCreate('t', items),
      /max 25/i,
    );
    assert.equal(stub.batchCreateCalls.length, 0, 'underlying not called on bad input');
  });

  // ---- Tarn #34: SDK invariant — refuse untagged writes to defined collections ----
  //
  // These tests pin down the guarantee that the untyped escape hatch can NEVER
  // produce a silent orphan in a defined collection. The same invariants the
  // typed Collection.create / batchCreate uphold (schema validation + Eid
  // stamping) now apply to advanced.entries.create / batchCreate as well.

  it('advanced.entries.create on a defined collection validates payload (missing primaryKey → TarnSchemaError)', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    // 'books' has required primaryKey 'bookId' — omit it.
    await assert.rejects(
      () => tarn.advanced.entries.create('books', { title: 'X' }),
      /required field 'bookId' is missing/,
    );
    // No wire call — validation fails before reaching the stub.
    assert.equal(stub.entries.length, 0);
  });

  it('advanced.entries.create on a defined collection rejects unknown fields (typo protection)', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    await assert.rejects(
      () => tarn.advanced.entries.create('books', { bookId: 'b1', titel: 'typo' }),
      /unknown field 'titel'/,
    );
    assert.equal(stub.entries.length, 0);
  });

  it('advanced.entries.create on a defined collection auto-stamps Eid + SchemaV', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    await tarn.advanced.entries.create('books', { bookId: 'b1', title: 'A' });
    assert.equal(stub.entries.length, 1);
    const tags = stub.entries[0]!.tags;
    const eid = tags.find((t) => t.name === 'Eid');
    const schemaV = tags.find((t) => t.name === 'SchemaV');
    assert.ok(eid, 'Eid must be auto-stamped on a defined-collection write');
    assert.ok(schemaV, 'SchemaV must be auto-stamped on a defined-collection write');
    assert.equal(schemaV.value, '4');
  });

  it('advanced.entries.create on an UNdefined type passes through with no validation or auto-stamp', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    // Schema-less type — escape hatch's legitimate use case. Random fields,
    // no Eid/SchemaV added by the SDK.
    await tarn.advanced.entries.create('app-cache-blob', { whatever: 'goes', here: 123 });
    assert.equal(stub.entries.length, 1);
    const tags = stub.entries[0]!.tags;
    assert.ok(!tags.find((t) => t.name === 'Eid'), 'no auto Eid for undefined type');
    assert.ok(!tags.find((t) => t.name === 'SchemaV'), 'no auto SchemaV for undefined type');
  });

  it('advanced.entries.create respects a caller-supplied Eid that matches the derived value', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    // Compute the canonical Eid the SDK would derive for (appId, type, pk).
    const derived = await deriveEid('bookish', 'books', 'b1');
    await tarn.advanced.entries.create(
      'books',
      { bookId: 'b1', title: 'A' },
      [{ name: 'Eid', value: derived }],
    );
    assert.equal(stub.entries.length, 1);
    const eidTags = stub.entries[0]!.tags.filter((t) => t.name === 'Eid');
    // No double-stamp: caller's Eid is respected, the auto one is suppressed.
    assert.equal(eidTags.length, 1, 'caller Eid must not be double-stamped');
    assert.equal(eidTags[0]!.value, derived);
  });

  it('advanced.entries.create throws TarnSchemaError when caller-supplied Eid does not match derived value', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    await assert.rejects(
      () => tarn.advanced.entries.create(
        'books',
        { bookId: 'b1', title: 'A' },
        [{ name: 'Eid', value: 'definitely-wrong' }],
      ),
      /caller-supplied Eid 'definitely-wrong' does not match/,
    );
    assert.equal(stub.entries.length, 0, 'no wire call on Eid mismatch');
  });

  it('advanced.entries.create round-trips: untyped write is then visible via the typed get path', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    // The whole point of the invariant: a record written through the escape
    // hatch must be reachable via the typed read path. Eid stamping is the
    // bridge — typed get derives Eid from primaryKey, the read path matches
    // on Eid, so the record surfaces.
    await tarn.advanced.entries.create('books', { bookId: 'b1', title: 'Round-Trip' });
    const tarnTyped = tarn as unknown as {
      books: { get(pk: string): Promise<{ bookId: string; title: string } | null> };
    };
    const read = await tarnTyped.books.get('b1');
    assert.ok(read, 'typed get should find the record written via advanced.entries.create');
    assert.equal(read.bookId, 'b1');
    assert.equal(read.title, 'Round-Trip');
  });

  it('advanced.entries.batchCreate on a defined collection reports all failing indexes (no partial writes)', async () => {
    const stub = new StubUnderlying();
    const tarn = await makeClient(stub);
    // Mix of valid + invalid items. Indexes 1 and 3 fail (missing primaryKey
    // and missing title respectively). Error must mention both; nothing
    // hits the wire.
    const items = [
      { bookId: 'b1', title: 'ok-0' },          // 0: ok
      { title: 'no-pk' },                       // 1: missing bookId
      { bookId: 'b2', title: 'ok-2' },          // 2: ok
      { bookId: 'b3' },                         // 3: missing title
    ];
    let thrown: unknown = null;
    try {
      await tarn.advanced.entries.batchCreate('books', items);
    } catch (err) {
      thrown = err;
    }
    assert.ok(thrown instanceof Error, 'must throw');
    const msg = (thrown as Error).message;
    assert.match(msg, /2\/4/, `error must report failure count; got: ${msg}`);
    assert.match(msg, /\[1\]/, `error must mention failing index 1; got: ${msg}`);
    assert.match(msg, /\[3\]/, `error must mention failing index 3; got: ${msg}`);
    assert.equal(stub.batchCreateCalls.length, 0, 'no wire call when any item fails');
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

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
  sendRecoveryKitEmailCalls = 0;

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
  async regenerateRecoveryKit(_opts?: Record<string, unknown>) {
    this.regenerateRecoveryKitCalls++;
    return {
      phrase: 'one two three four five six seven eight nine ten eleven twelve',
      pdfBytes: new Uint8Array([0x25, 0x50, 0x44, 0x46]), // %PDF
    };
  }
  async sendRecoveryKitEmail(_args: {
    recipientEmail: string;
    pdfBytes: Uint8Array;
    appName?: string;
    subject?: string;
  }) {
    this.sendRecoveryKitEmailCalls++;
    return { ok: true };
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
  async listIncomingRequests() {
    this.listIncomingRequestsCalls++;
    return [];
  }
  async createInviteToken() {
    this.createInviteTokenCalls++;
    return { token: 'stub-invite' };
  }
  async redeemInviteToken(_t: string, _k: string) {
    this.redeemInviteTokenCalls++;
    return { ok: true };
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

  it('connections.mute / unmute / isMuted delegate', async () => {
    const c = { share_pub: 'sp1', signing_pub: 'sg1' };
    await tarn.connections.mute(c);
    assert.equal(stub.muteCalls, 1);
    assert.equal(await tarn.connections.isMuted(c), true);
    await tarn.connections.unmute(c);
    assert.equal(stub.unmuteCalls, 1);
    assert.equal(await tarn.connections.isMuted(c), false);
  });

  it('account.changeCredentials delegates', async () => {
    await tarn.account.changeCredentials('new@e.com', 'newpw');
    assert.equal(stub.changeCredentialsCalls, 1);
  });

  it('recovery.export({ format: pdf }) returns the PDF bytes', async () => {
    const result = await tarn.recovery.export({ format: 'pdf' });
    assert.ok(result instanceof Uint8Array);
    assert.equal(stub.regenerateRecoveryKitCalls, 1);
  });

  it('recovery.export({ format: json }) returns the structured kit', async () => {
    const result = await tarn.recovery.export({ format: 'json', appName: 'Bookish' });
    assert.ok(!(result instanceof Uint8Array));
    const json = result as { phrase: string; appName: string; generatedAt: string };
    assert.ok(json.phrase.length > 0);
    assert.equal(json.appName, 'Bookish');
    assert.ok(json.generatedAt);
  });

  it('recovery.emailKit forwards', async () => {
    const pdfBytes = new Uint8Array([1, 2, 3]);
    await tarn.recovery.emailKit({ to: 'r@e.com', pdfBytes });
    assert.equal(stub.sendRecoveryKitEmailCalls, 1);
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

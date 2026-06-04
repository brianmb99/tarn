/**
 * TarnClient — the schema-aware, typed top-level surface of the SDK.
 *
 * App-facing model:
 *   const tarn = await TarnClient.create({ apiBase, appId, schema, storage });
 *   await tarn.login(username, password);
 *   await tarn.<collection>.create({...});         // typed from schema
 *   await tarn.connections.list();
 *   await tarn.session.clear();
 *
 * Implementation: wraps the existing JS TarnClient (in tarn.js) — step 6 of
 * the migration ports the underlying client to TS without changing any of
 * the public surface in this file.
 */

import type {
  CollectionDef,
  Schema,
  SchemaInput,
} from '../schema/index.js';
import { Collection, type ITarnClient } from '../collections/index.js';
import type { TarnStorageAdapter } from '../storage/index.js';
import type { AnySchema, ClientConfig, CollectionsOf } from './types.js';
import { ConnectionsNamespace, type IConnectionsClient } from './namespaces/connections.js';
import { AccountNamespace, type IAccountClient } from './namespaces/account.js';
import { SessionNamespace, type ISessionClient } from './namespaces/session.js';
import { AccountKeyNamespace, type IAccountKeyClient } from './namespaces/recovery.js';
import { PasskeysNamespace, type IPasskeysClient } from './namespaces/passkeys.js';
import { AdvancedNamespace, type IAdvancedClient } from './namespaces/advanced.js';

// The bundled legacy protocol client. Now that tarn.ts is itself TypeScript
// (steps 6a-6d), the new typed surface can default-instantiate the underlying
// client without forcing every app to thread an `underlying` factory through
// `TarnClient.create()`. Tests still override via `config.underlying` to
// inject stub IUnderlyingClient implementations.
import { TarnClient as LegacyTarnClient } from '../tarn.js';

/**
 * Combined interface the underlying JS client must satisfy. Composed from
 * the per-namespace interfaces so each namespace is independently testable
 * with a stub.
 */
export type IUnderlyingClient =
  & ITarnClient
  & IConnectionsClient
  & IAccountClient
  & ISessionClient
  & IAccountKeyClient
  & IPasskeysClient
  & IAdvancedClient
  & {
    // Auth lifecycle.
    register(username: string, password: string, opts?: Record<string, unknown>): Promise<unknown>;
    login(username: string, password: string, opts?: Record<string, unknown>): Promise<unknown>;
    recoverAccount(args: Record<string, unknown>): Promise<unknown>;
    serializeSession(): Promise<string>;
  };

/**
 * Factory function — produces the underlying protocol client given (apiBase,
 * appId). Apps don't need to supply this in normal use; the default factory
 * instantiates the bundled legacy client. Override only for testing
 * (inject a stub IUnderlyingClient) or when threading a custom protocol
 * implementation through.
 */
export type UnderlyingFactory = (apiBase: string, appId: string) => IUnderlyingClient;

export type TarnClientCreateConfig<S extends AnySchema> = ClientConfig<S> & {
  /**
   * Optional: override the underlying protocol-layer client. Defaults to
   * the bundled legacy TarnClient (which speaks the wire protocol). Tests
   * pass a stub here; production apps leave it unset.
   *
   * Note: when this is supplied, session resume is skipped — the SDK
   * doesn't know how to resume an arbitrary stub-shaped client. Tests that
   * want to exercise the resume path use the default factory.
   */
  underlying?: UnderlyingFactory;
};

/**
 * Hook signature for the resume path: given the persisted session blob,
 * produce a logged-in underlying client, or null if the blob is stale /
 * corrupt / for a different account.
 *
 * The default resumer wraps the bundled legacy client's static
 * `resumeSession`. Tests use the helper `resolveUnderlying()` directly to
 * inject mocks.
 */
type Resumer = (apiBase: string, appId: string, blob: string) => Promise<IUnderlyingClient | null>;

/**
 * The typed client. Generic over the schema so `tarn.<collection>` is fully
 * inferred. Apps don't construct this directly — use the static `create()`
 * factory.
 */
export class TarnClient<S extends AnySchema> {
  readonly #underlying: IUnderlyingClient;
  readonly #storage: TarnStorageAdapter;
  readonly #schema: S;
  readonly #appId: string;

  // Lifecycle namespaces.
  readonly connections: ConnectionsNamespace;
  readonly account: AccountNamespace;
  readonly session: SessionNamespace;
  readonly accountKey: AccountKeyNamespace;
  readonly passkeys: PasskeysNamespace;
  readonly advanced: AdvancedNamespace;

  // Dynamic collection namespace — populated from the schema in `create()`.
  // The intersection cast in `create()` exposes this as `tarn.<collectionName>`
  // with full TS inference.
  readonly collections: CollectionsOf<S>;

  private constructor(args: {
    underlying: IUnderlyingClient;
    storage: TarnStorageAdapter;
    schema: S;
    appId: string;
    collections: CollectionsOf<S>;
  }) {
    this.#underlying = args.underlying;
    this.#storage = args.storage;
    this.#schema = args.schema;
    this.#appId = args.appId;
    this.collections = args.collections;

    this.connections = new ConnectionsNamespace(args.underlying);
    this.account = new AccountNamespace(args.underlying, () => this.#onLogout());
    this.session = new SessionNamespace(args.underlying, () => this.#onLogout());
    this.accountKey = new AccountKeyNamespace(args.underlying, args.appId);
    this.passkeys = new PasskeysNamespace(args.underlying);

    // Schema info for the advanced surface: it validates payloads and
    // auto-stamps Eid + SchemaV whenever a caller writes to a `type` that
    // corresponds to a defined collection. Keeps the escape hatch from
    // silently creating orphans (or accepting records that violate the
    // declared schema) in typed collections, while preserving schema-less
    // semantics for unknown types (share-state, app-internal, etc.).
    const collectionsByType = new Map<string, CollectionDef>();
    const schemaInner = args.schema as unknown as {
      collections: Record<string, CollectionDef>;
      version: number;
    };
    for (const [name, def] of Object.entries(schemaInner.collections)) {
      collectionsByType.set(name, def);
    }
    this.advanced = new AdvancedNamespace(args.underlying, {
      collectionsByType,
      schemaVersion: schemaInner.version,
      appId: args.appId,
    });
  }

  /**
   * Construct a TarnClient. Resumes any persisted session via the storage
   * adapter — if the resume succeeds, the returned client is already
   * logged in. Otherwise, the app calls `login()` or `register()`.
   */
  static async create<S extends AnySchema>(
    config: TarnClientCreateConfig<S>,
  ): Promise<TarnClient<S> & CollectionsOf<S>> {
    if (typeof config?.apiBase !== 'string') throw new Error('TarnClient.create: apiBase required');
    if (typeof config?.appId !== 'string') throw new Error('TarnClient.create: appId required');
    if (!config.schema) throw new Error('TarnClient.create: schema required');
    if (!config.storage) throw new Error('TarnClient.create: storage required');

    if ((config.schema as { appId: string }).appId !== config.appId) {
      throw new Error(
        `TarnClient.create: schema.appId ('${(config.schema as { appId: string }).appId}') does not match config.appId ('${config.appId}')`,
      );
    }

    // Resolve the underlying client: if a factory is provided (test path),
    // instantiate via the factory and skip resume. Otherwise: read storage,
    // try to resume a persisted session via the bundled legacy client's
    // static `resumeSession`, fall back to a fresh instance on miss /
    // failure (clearing the stale blob so we don't retry on every reload).
    const fresh = (): IUnderlyingClient => {
      if (config.underlying) return config.underlying(config.apiBase, config.appId);
      return new LegacyTarnClient(config.apiBase, config.appId) as unknown as IUnderlyingClient;
    };
    const resume: Resumer | null = config.underlying
      ? null
      : async (api, app, blob) => {
          const resumed = await LegacyTarnClient.resumeSession(api, app, blob);
          return resumed ? (resumed as unknown as IUnderlyingClient) : null;
        };
    const underlying = await resolveUnderlying({
      apiBase: config.apiBase,
      appId: config.appId,
      storage: config.storage,
      resume,
      fresh,
    });

    // Build the collection namespace from the schema.
    const collections = await buildCollections<S>(underlying, config.schema, config.appId);

    const client = new TarnClient<S>({
      underlying,
      storage: config.storage,
      schema: config.schema,
      appId: config.appId,
      collections,
    });

    // Compose the public shape: the class instance plus the
    // tarn.<collection> properties from `collections`. The cast carries
    // the dynamic key set into the type system; runtime is just an
    // assignment.
    Object.assign(client as unknown as Record<string, unknown>, collections);
    return client as TarnClient<S> & CollectionsOf<S>;
  }

  // ============ Auth (top-level) ============

  /**
   * Register a new account with this app. On success the client is logged
   * in (subsequent `tarn.<collection>` calls work) and the session is
   * persisted via the storage adapter.
   */
  async register(username: string, password: string, opts: Record<string, unknown> = {}): Promise<unknown> {
    const result = await this.#underlying.register(username, password, opts);
    await this.#persistSession();
    return result;
  }

  /**
   * Log into an existing account. On success the client is logged in and
   * the session is persisted.
   */
  async login(username: string, password: string, opts: Record<string, unknown> = {}): Promise<unknown> {
    const result = await this.#underlying.login(username, password, opts);
    await this.#persistSession();
    return result;
  }

  /**
   * Recover an account from an account key. New username + password establish
   * fresh credentials; the prior data is preserved (forward-secret DEK chain).
   */
  async recoverAccount(args: Record<string, unknown>): Promise<unknown> {
    const result = await this.#underlying.recoverAccount(args);
    await this.#persistSession();
    return result;
  }

  /**
   * Authenticate with a registered passkey (Phase 6). Triggers the
   * platform authenticator prompt; on success the client is logged in
   * exactly as if the user had called `login()`.
   *
   * Apps decide which auth path to surface (passkey-first, password-
   * first, both side-by-side). Passkey auth requires PRF support — see
   * `tarn.passkeys.isSupported()`.
   */
  async authenticateWithPasskey(opts: {
    deviceLabel?: string;
    credentialId?: string;
    stalePasskeyHandler?: () => Promise<{ username: string; password: string } | null>;
  } = {}): Promise<unknown> {
    const result = await this.#underlying.authenticateWithPasskey(opts);
    await this.#persistSession();
    return result;
  }

  /** Convenience — same as `tarn.session.isLoggedIn()`. */
  isLoggedIn(): boolean {
    return this.#underlying.isLoggedIn();
  }

  // ============ Internal ============

  async #persistSession(): Promise<void> {
    try {
      const blob = await this.#underlying.serializeSession();
      await this.#storage.write(blob);
    } catch (err) {
      // Non-fatal — the user is logged in for this session even if persistence
      // fails. They'll need to re-login on reload.
      console.warn('[TarnClient] persist session failed:', err instanceof Error ? err.message : err);
    }
  }

  #onLogout(): void {
    void this.#storage.clear().catch((err: unknown) => {
      console.warn('[TarnClient] clear session failed:', err instanceof Error ? err.message : err);
    });
  }
}

// ============ Collection namespace builder ============

async function buildCollections<S extends AnySchema>(
  underlying: ITarnClient,
  schema: S,
  appId: string,
): Promise<CollectionsOf<S>> {
  const out: Record<string, Collection<Record<string, unknown>>> = {};
  const collections = (schema as unknown as SchemaInput).collections;
  const version = (schema as unknown as SchemaInput).version;

  for (const [name, def] of Object.entries(collections)) {
    out[name] = new Collection({
      client: underlying,
      appId,
      name,
      def: def as CollectionDef,
      schemaVersion: version,
    });
  }

  return out as unknown as CollectionsOf<S>;
}

// ============ Underlying-resolution helper ============

/**
 * Pick the underlying client for a new TarnClient: try to resume a persisted
 * session; on miss / failure, build a fresh instance and clear any stale blob.
 *
 * Exported (under a `_` prefix) so unit tests can drive it directly with
 * mock storage adapters and a stub resumer — the production path through
 * `TarnClient.create()` does not let tests inject a custom resumer.
 *
 * @internal
 */
export async function resolveUnderlying(args: {
  apiBase: string;
  appId: string;
  storage: TarnStorageAdapter;
  /** Null disables resume entirely (e.g., when a test factory is in use). */
  resume: ((apiBase: string, appId: string, blob: string) => Promise<IUnderlyingClient | null>) | null;
  fresh: () => IUnderlyingClient;
}): Promise<IUnderlyingClient> {
  if (!args.resume) return args.fresh();

  let blob: string | null = null;
  try {
    blob = await args.storage.read();
  } catch (err) {
    // Storage backends can fail (quota, permission). Treat as "no blob"
    // and construct fresh — the user re-authenticates and the next
    // login() persists, which surfaces any persistent storage failure.
    console.warn('[TarnClient] storage read failed:', err instanceof Error ? err.message : err);
    return args.fresh();
  }
  if (!blob) return args.fresh();

  let resumed: IUnderlyingClient | null = null;
  try {
    resumed = await args.resume(args.apiBase, args.appId, blob);
  } catch (err) {
    console.warn('[TarnClient] resume failed:', err instanceof Error ? err.message : err);
  }
  if (resumed) return resumed;

  // Blob was stale, corrupt, expired, or for a different account. Clear
  // it so we don't re-attempt resume on every page load.
  try {
    await args.storage.clear();
  } catch {
    // Non-fatal — the next persistSession() will overwrite anyway.
  }
  return args.fresh();
}

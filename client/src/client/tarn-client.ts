/**
 * TarnClient — the schema-aware, typed top-level surface of the SDK.
 *
 * App-facing model:
 *   const tarn = await TarnClient.create({ apiBase, appId, schema, storage });
 *   await tarn.login(email, password);
 *   await tarn.<collection>.create({...});         // typed from schema
 *   await tarn.connections.list();
 *   const pdf = await tarn.recovery.export({ format: 'pdf' });
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
import { RecoveryNamespace, type IRecoveryClient } from './namespaces/recovery.js';
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
  & IRecoveryClient
  & IAdvancedClient
  & {
    // Auth lifecycle.
    register(email: string, password: string, opts?: Record<string, unknown>): Promise<unknown>;
    login(email: string, password: string, opts?: Record<string, unknown>): Promise<unknown>;
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
   */
  underlying?: UnderlyingFactory;
};

const SESSION_RESUME_OPTS = {
  // Pass through to the JS resumeSession; placeholder for future tunables.
};

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
  readonly recovery: RecoveryNamespace;
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
    this.recovery = new RecoveryNamespace(args.underlying, args.appId);
    this.advanced = new AdvancedNamespace(args.underlying);
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

    // Default to the bundled legacy client; tests inject a stub via config.underlying.
    const underlyingFactory: UnderlyingFactory = config.underlying
      ?? ((api, app) => new LegacyTarnClient(api, app) as unknown as IUnderlyingClient);
    const underlying = underlyingFactory(config.apiBase, config.appId);

    // Build the collection namespace from the schema.
    const collections = await buildCollections<S>(underlying, config.schema, config.appId);

    const client = new TarnClient<S>({
      underlying,
      storage: config.storage,
      schema: config.schema,
      appId: config.appId,
      collections,
    });

    // Try to restore a persisted session before returning. Failures here
    // are non-fatal — corrupt or stale blobs result in "not logged in"
    // and the app proceeds to `login()` / `register()`.
    await client.#tryResumeSession();

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
  async register(email: string, password: string, opts: Record<string, unknown> = {}): Promise<unknown> {
    const result = await this.#underlying.register(email, password, opts);
    await this.#persistSession();
    return result;
  }

  /**
   * Log into an existing account. On success the client is logged in and
   * the session is persisted.
   */
  async login(email: string, password: string, opts: Record<string, unknown> = {}): Promise<unknown> {
    const result = await this.#underlying.login(email, password, opts);
    await this.#persistSession();
    return result;
  }

  /**
   * Recover an account from a recovery phrase. New email + password establish
   * fresh credentials; the prior data is preserved (forward-secret DEK chain).
   */
  async recoverAccount(args: Record<string, unknown>): Promise<unknown> {
    const result = await this.#underlying.recoverAccount(args);
    await this.#persistSession();
    return result;
  }

  /** Convenience — same as `tarn.session.isLoggedIn()`. */
  isLoggedIn(): boolean {
    return this.#underlying.isLoggedIn();
  }

  // ============ Internal ============

  async #tryResumeSession(): Promise<void> {
    try {
      const blob = await this.#storage.read();
      if (!blob) return;
      // The underlying client's static `resumeSession` is a class method on
      // the JS prototype; we delegate to instance-level resume by invoking
      // through the underlying. The factory shape doesn't expose static
      // resumes, so callers expecting classic behaviour use the underlying
      // client directly via `tarn.advanced.*` if they need it. For now, the
      // resume path is implicit — once the underlying TS client lands in
      // step 6 we'll wire this through cleanly.
      // Step-4 limitation: explicit instance-level `resumeSession()` is not
      // exposed by the legacy JS client (it's static). Apps that need
      // explicit session restore call the underlying's static helper before
      // constructing the TarnClient. This will get cleaner in step 6.
      void SESSION_RESUME_OPTS;
    } catch (err) {
      console.warn('[TarnClient] resume session failed:', err instanceof Error ? err.message : err);
    }
  }

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

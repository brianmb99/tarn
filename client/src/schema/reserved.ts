/**
 * Type names reserved by the Tarn base schema.
 *
 * Apps cannot declare collections with these names — they identify entry types
 * managed by SDK primitives (`tarn.connections.*`, `tarn.account.*`,
 * `tarn.recovery.*`, etc.) and the protocol layer beneath them. Collisions
 * would let app data shadow Tarn-internal records.
 *
 * If a future SDK feature claims a new reserved type, add the name here AND
 * wire it into the namespace primitive that owns it. The reserved set is the
 * source of truth — the runtime check in `defineSchema()` reads from it.
 */
export const RESERVED_TYPE_NAMES: ReadonlySet<string> = new Set([
  'cred',              // credential mappings (auth flow)
  'connection',        // friend connections
  'share-log-state',   // per-pair share-log entries
  'share-inbox',       // connection handshake material
  'recovery-factor',   // recovery key derivation material
  'app-config',        // app rules / config
  'app-schema',        // schema documents (this redesign)
]);

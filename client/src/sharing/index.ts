/**
 * Public surface of the sharing module.
 *
 * Step 3 ships the typed Connection object and the related types consumed
 * by the Collection sharing methods. The connection lifecycle methods
 * (`tarn.connections.invite`, `accept`, `list`, `mute`, etc.) move into
 * `tarn.connections.*` namespace in step 4.
 */

export type {
  Connection,
  ShareLogEntry,
  ShareWithAllResult,
  InviteToken,
  CreateInviteOpts,
  InvitePreview,
  IssuedInvite,
  RedeemedInvite,
  IncomingRequest,
  ListIncomingOpts,
} from './types.js';

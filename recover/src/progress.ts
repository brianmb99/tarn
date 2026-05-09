/**
 * Progress signalling for the {@link import('./recover.js').recover}
 * orchestrator and {@link import('./reader/reader.js').Reader}.
 *
 * The plan (see `docs/STANDALONE_RECOVERY_PLAN.md` §"API shape") names six
 * stages; the reader phases re-fire stages as it walks each collection.
 *
 * `onProgress` is purely diagnostic — apps render spinners with it. The
 * orchestrator never lets a callback exception break the recovery flow.
 */

export type RecoverStage =
  | 'deriving'
  | 'locating-account'
  | 'fetching-envelope'
  | 'walking-log'
  | 'decrypting'
  | 'done';

export type RecoverProgress = {
  stage: RecoverStage;
  /** Free-form context: collection name, current/total counts, etc. */
  info: Record<string, unknown>;
};

export type OnProgress = (
  stage: RecoverStage,
  info: Record<string, unknown>,
) => void;

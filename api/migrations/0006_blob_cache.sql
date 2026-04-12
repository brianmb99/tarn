-- Cache encrypted blob data in D1 alongside entry metadata.
-- Eliminates client-side Arweave gateway fetches during normal reads.
-- Blobs are < 100KB (enforced by max_bytes rule). D1 row limit is 1MB.

ALTER TABLE entries ADD COLUMN blob_data BLOB;

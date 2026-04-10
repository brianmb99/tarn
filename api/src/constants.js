// Shared constants for fee schedule, protocol wallet, and upload limits

export const PROTOCOL_WALLET = '0x7dbb8Bf8359dF93146A4656EB1292fcB1fd9a500';
export const EXPECTED_FEE_WEI = '4700000000000'; // 0.0000047 ETH = 4.7e12 wei
export const MAX_UPLOAD_BYTES = 102400; // 100 KiB
export const FEE_EXEMPT_TYPES = new Set(['cred', 'acct']);

export const FEE_SCHEDULE = {
  fee: EXPECTED_FEE_WEI,
  currency: 'ETH',
  network: 'base',
  chainId: 8453,
  address: PROTOCOL_WALLET,
  feeVersion: 3,
  maxBytes: MAX_UPLOAD_BYTES,
};

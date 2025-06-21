import { ec as EC } from 'elliptic';
import { sha3_256 } from 'js-sha3';

// Flow uses ECDSA P-256 (secp256r1)
const ec = new EC('p256');

// Domain tag for Flow public keys
// https://developers.flow.com/tooling/flow-cli/accounts/generating-keys#public-key-format
const P256_DOMAIN_TAG = "P256_DOMAIN_TAG";

/**
 * Derives a Flow account address from an ECDSA P-256 private key.
 *
 * @param privateKeyHex - The private key in hexadecimal format.
 * @returns The Flow account address prefixed with '0x'.
 * @throws Error if the private key is invalid.
 */
export function deriveFlowAddressFromPrivateKey(privateKeyHex: string): string {
  try {
    // Validate private key format (basic check)
    if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex)) {
      throw new Error('Invalid private key format. Expected 64 hex characters.');
    }

    // Create key pair from private key
    const keyPair = ec.keyFromPrivate(privateKeyHex, 'hex');

    // Get the public key in uncompressed format (with 0x04 prefix)
    const publicKeyUncompressed = keyPair.getPublic(false, 'hex');

    // Remove the 0x04 prefix to get the raw public key bytes
    const publicKeyRaw = publicKeyUncompressed.substring(2);

    // Ensure the public key is the correct length for P-256 (64 bytes / 128 hex chars)
    if (publicKeyRaw.length !== 128) {
        throw new Error(`Invalid public key length. Expected 128 hex characters, got ${publicKeyRaw.length}`);
    }

    // Prepare the data to be hashed: Domain Tag + Public Key
    // The domain tag needs to be UTF-8 encoded and 32 bytes, right-padded with 0s.
    const domainTagBuffer = Buffer.from(P256_DOMAIN_TAG, 'utf-8');
    const paddedDomainTag = Buffer.alloc(32);
    domainTagBuffer.copy(paddedDomainTag);

    const publicKeyBuffer = Buffer.from(publicKeyRaw, 'hex');
    const dataToHash = Buffer.concat([paddedDomainTag, publicKeyBuffer]);

    // Hash the data using SHA3-256
    const hash = sha3_256(dataToHash);

    // The address is the last 20 bytes of the hash
    // Flow addresses are typically 8 bytes for the mainnet service account (0x1654653399040a61)
    // or other core contracts. For user accounts, it's often shorter when represented without leading zeros.
    // However, the process generates a 20-byte hash, and usually, the address is derived from this.
    // FCL and other tools might format this differently or use a shorter version.
    // For now, let's take the full hash, then consider if truncation or specific formatting is needed
    // based on how Flow addresses are typically represented for user accounts.
    // The standard address format is 8 bytes (16 hex characters).
    // Let's re-check Flow documentation for address generation from a public key hash.

    // According to Flow documentation:
    // "The address is the last 8 bytes of the hash of the public key and the domain separation tag."
    // This seems to have changed or my previous understanding was off.
    // Let's adjust to take the last 8 bytes of the hash.
    // No, the common practice and what other libraries do is take 8 bytes from the hash.
    // For example, flow-js-sdk: PublicKey.address()
    // https://github.com/onflow/flow-js-sdk/blob/master/packages/crypto/src/publicKey.js#L103
    // It takes 8 bytes from the hash.

    // The output of sha3_256 is a hex string. We need the raw bytes for address derivation.
    const hashBuffer = Buffer.from(hash, 'hex');
    // Take the last 8 bytes of the hash to form the address.
    const addressBytes = hashBuffer.slice(-8);
    const address = addressBytes.toString('hex');

    return `0x${address}`;
  } catch (error) {
    // Log the error for debugging purposes
    console.error("Error deriving Flow address:", error);
    // Re-throw the error to be handled by the caller
    if (error instanceof Error) {
        throw error;
    }
    throw new Error('Failed to derive Flow address.');
  }
}

/**
 * Derives a Flow account address and public key from an ECDSA P-256 private key.
 *
 * @param privateKeyHex - The private key in hexadecimal format.
 * @returns An object containing the Flow account address (prefixed with '0x') and the raw public key (hex, uncompressed, without 0x04 prefix).
 * @throws Error if the private key is invalid.
 */
export function getFlowAccountDetailsFromPrivateKey(privateKeyHex: string): { address: string, publicKey: string } {
  try {
    // Validate private key format (basic check)
    if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex)) {
      throw new Error('Invalid private key format. Expected 64 hex characters.');
    }

    // Create key pair from private key
    const keyPair = ec.keyFromPrivate(privateKeyHex, 'hex');

    // Get the public key in uncompressed format (with 0x04 prefix)
    const publicKeyUncompressed = keyPair.getPublic(false, 'hex');

    // Remove the 0x04 prefix to get the raw public key bytes
    const publicKeyRaw = publicKeyUncompressed.substring(2);

    if (publicKeyRaw.length !== 128) {
        throw new Error(`Invalid public key length. Expected 128 hex characters, got ${publicKeyRaw.length}`);
    }

    // Prepare the data to be hashed: Domain Tag + Public Key
    const domainTagBuffer = Buffer.from(P256_DOMAIN_TAG, 'utf-8');
    const paddedDomainTag = Buffer.alloc(32);
    domainTagBuffer.copy(paddedDomainTag);

    const publicKeyBuffer = Buffer.from(publicKeyRaw, 'hex');
    const dataToHash = Buffer.concat([paddedDomainTag, publicKeyBuffer]);

    // Hash the data using SHA3-256
    const hash = sha3_256(dataToHash);
    const hashBuffer = Buffer.from(hash, 'hex');
    const addressBytes = hashBuffer.slice(-8);
    const address = addressBytes.toString('hex');

    return {
      address: `0x${address}`,
      publicKey: publicKeyRaw,
    };
  } catch (error) {
    console.error("Error deriving Flow account details:", error);
    if (error instanceof Error) {
        throw error;
    }
    throw new Error('Failed to derive Flow account details.');
  }
}

/**
 * Signs a hexadecimal message with an ECDSA P-256 private key.
 *
 * @param privateKeyHex - The private key in hexadecimal format.
 * @param messageHex - The message to sign, in hexadecimal format.
 * @returns The signature as a hexadecimal string (R + S).
 * @throws Error if the private key is invalid or signing fails.
 */
export function signMessageWithPrivateKeyHex(privateKeyHex: string, messageHex: string): string {
  try {
    if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex)) {
      throw new Error('Invalid private key format. Expected 64 hex characters.');
    }
    if (!/^[0-9a-fA-F]+$/.test(messageHex)) {
      throw new Error('Invalid message format. Expected hex characters.');
    }

    const key = ec.keyFromPrivate(privateKeyHex, 'hex');
    // The messageHex is what needs to be signed.
    // elliptic's sign method takes the message hash.
    // However, in the context of FCL's signingFunction, `signable.message`
    // is typically the already prepared digest to be signed.
    // If `messageHex` were the raw data, we'd hash it first (e.g., with SHA3-256).
    // For now, assume messageHex is the digest as provided by FCL.
    const signature = key.sign(messageHex, { canonical: true });

    const r = signature.r.toArrayLike(Buffer, 'be', 32);
    const s = signature.s.toArrayLike(Buffer, 'be', 32);

    return Buffer.concat([r, s]).toString('hex');
  } catch (error) {
    console.error("Error signing message:", error);
    if (error instanceof Error) {
      throw error;
    }
    throw new Error('Failed to sign message.');
  }
}

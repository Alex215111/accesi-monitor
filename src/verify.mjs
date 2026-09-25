/**
 * @module verify
 * Pure checks for the release manifest: parse it, verify its ES256 signature with the pinned public key, compare a downloaded file
 * with its SHA-384 hash and compare sequence numbers. No network and no file access, so every rule is unit tested. Never prints
 * the content of a file, only names and reasons.
 */
import { createHash, webcrypto } from 'node:crypto';

/** Prefix that separates the manifest signature from every other signature made by the same tooling (ADR 0031, section 7). */
export const SIGNING_PREFIX = 'wc-manifest/v1\n';

const FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const SRI_SHA384 = /^sha384-[A-Za-z0-9+/]{64}$/;

/**
 * Decodes base64url text.
 * @param {string} text - Base64url text, without padding.
 * @returns {Uint8Array} The bytes.
 */
export function base64UrlToBytes(text) {
  return new Uint8Array(Buffer.from(text.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
}

/**
 * Checks that a JWK is a public P-256 key: a key with a private part (`d`) must never be pinned here.
 * @param {unknown} jwk - Parsed content of `keys/manifest.pub.json`.
 * @returns {object} The same key when it is valid.
 * @throws {Error} When it is not a public EC P-256 JWK.
 */
export function assertPublicKey(jwk) {
  if (typeof jwk !== 'object' || jwk === null) throw new Error('the pinned key is not an object');
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw new Error('the pinned key must be an EC P-256 JWK');
  if ('d' in jwk) throw new Error('the pinned key contains a private part (d)');
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string') throw new Error('the pinned key has no x and y');
  return jwk;
}

/**
 * Parses and validates the manifest.
 * @param {Uint8Array|Buffer} manifestBytes - Exact bytes that were signed.
 * @returns {{version: string, sequence: number, issuedAt: string, files: Record<string, string>}} The manifest.
 * @throws {Error} When the shape is wrong, a file name is unsafe or a hash is not `sha384-` plus base64.
 */
export function parseManifest(manifestBytes) {
  const manifest = JSON.parse(Buffer.from(manifestBytes).toString('utf8'));
  if (typeof manifest.version !== 'string' || manifest.version === '') throw new Error('manifest without version');
  if (!Number.isInteger(manifest.sequence) || manifest.sequence < 1) throw new Error('manifest without a valid sequence');
  if (typeof manifest.issuedAt !== 'string') throw new Error('manifest without issuedAt');
  const files = manifest.files;
  if (typeof files !== 'object' || files === null || Object.keys(files).length === 0) throw new Error('manifest without files');
  for (const [name, hash] of Object.entries(files)) {
    if (!FILE_NAME.test(name)) throw new Error(`unsafe file name in the manifest: ${name}`);
    if (typeof hash !== 'string' || !SRI_SHA384.test(hash)) throw new Error(`bad hash for ${name}`);
  }
  return manifest;
}

/**
 * Verifies the ES256 signature of a manifest.
 * @param {object} options - The manifest, its signature and the pinned key.
 * @param {Uint8Array|Buffer} options.manifestBytes - Exact bytes of `manifest.json`.
 * @param {string} options.signature - Base64url of the raw 64-byte signature (r followed by s).
 * @param {object} options.publicJwk - The pinned public key.
 * @returns {Promise<boolean>} True only when the signature is valid for this key and these bytes.
 */
export async function verifyManifestSignature({ manifestBytes, signature, publicJwk }) {
  const key = await webcrypto.subtle.importKey(
    'jwk',
    assertPublicKey(publicJwk),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
  const signed = Buffer.concat([Buffer.from(SIGNING_PREFIX), Buffer.from(manifestBytes)]);
  return webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, base64UrlToBytes(signature.trim()), signed);
}

/**
 * Computes the SRI hash of some bytes.
 * @param {Uint8Array|Buffer} bytes - File content.
 * @returns {string} `sha384-` followed by the base64 digest.
 */
export function sriSha384(bytes) {
  return `sha384-${createHash('sha384').update(bytes).digest('base64')}`;
}

/**
 * Lists the files whose hash differs from the manifest.
 * @param {Record<string, string>} expected - Hashes from the signed manifest.
 * @param {Record<string, Uint8Array|Buffer|null>} actual - Downloaded bytes by file name; `null` when it could not be downloaded.
 * @returns {string[]} One message per file that is missing or different; empty when everything matches.
 */
export function compareFiles(expected, actual) {
  const problems = [];
  for (const [name, hash] of Object.entries(expected)) {
    const bytes = actual[name];
    if (bytes === null || bytes === undefined) problems.push(`${name}: could not be downloaded`);
    else if (sriSha384(bytes) !== hash) problems.push(`${name}: hash differs from the signed manifest`);
  }
  return problems;
}

/**
 * Rejects a manifest whose sequence is lower than the previous one (a rollback to an older, signed manifest).
 * @param {number} previous - Sequence of the manifest on the base branch.
 * @param {number} next - Sequence of the new manifest.
 * @returns {boolean} True when the new sequence is at least the previous one.
 */
export function sequenceIsNotLower(previous, next) {
  return next >= previous;
}

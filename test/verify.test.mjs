// Tests for src/verify.mjs: a valid manifest passes; a changed hash, a wrong key, another signing domain, an unsigned or rolled back
// manifest and a private key in the pinned file are all rejected.
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import test from 'node:test';
import {
  SIGNING_PREFIX,
  assertPublicKey,
  compareFiles,
  parseManifest,
  sequenceIsNotLower,
  sriSha384,
  verifyManifestSignature,
} from '../src/verify.mjs';

const toBase64Url = (bytes) => Buffer.from(bytes).toString('base64url');

async function newKey() {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return { privateKey: pair.privateKey, publicJwk: await webcrypto.subtle.exportKey('jwk', pair.publicKey) };
}

async function sign(privateKey, manifestBytes, prefix = SIGNING_PREFIX) {
  const data = Buffer.concat([Buffer.from(prefix), Buffer.from(manifestBytes)]);
  return toBase64Url(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data));
}

const loader = Buffer.from('(()=>{})();');
const manifestBytes = Buffer.from(
  JSON.stringify({ version: '1.0.0', sequence: 3, issuedAt: '2026-09-25T00:00:00Z', files: { 'loader.js': sriSha384(loader) } }),
);

test('accepts a manifest signed with the pinned key', async () => {
  const { privateKey, publicJwk } = await newKey();
  const signature = await sign(privateKey, manifestBytes);
  assert.equal(await verifyManifestSignature({ manifestBytes, signature, publicJwk }), true);
});

test('rejects a manifest whose bytes were altered after signing', async () => {
  const { privateKey, publicJwk } = await newKey();
  const signature = await sign(privateKey, manifestBytes);
  const altered = Buffer.from(manifestBytes.toString().replace('1.0.0', '1.0.1'));
  assert.equal(await verifyManifestSignature({ manifestBytes: altered, signature, publicJwk }), false);
});

test('rejects a manifest signed with another key (for example the configuration key)', async () => {
  const pinned = await newKey();
  const other = await newKey();
  const signature = await sign(other.privateKey, manifestBytes);
  assert.equal(await verifyManifestSignature({ manifestBytes, signature, publicJwk: pinned.publicJwk }), false);
});

test('rejects a signature made for another signing domain (configuration prefix)', async () => {
  const { privateKey, publicJwk } = await newKey();
  const signature = await sign(privateKey, manifestBytes, 'wc-config/v1\n');
  assert.equal(await verifyManifestSignature({ manifestBytes, signature, publicJwk }), false);
});

test('rejects an empty or truncated signature', async () => {
  const { publicJwk } = await newKey();
  assert.equal(await verifyManifestSignature({ manifestBytes, signature: '', publicJwk }), false);
  assert.equal(await verifyManifestSignature({ manifestBytes, signature: 'AAAA', publicJwk }), false);
});

test('refuses a pinned key that has a private part', async () => {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const privateJwk = await webcrypto.subtle.exportKey('jwk', pair.privateKey);
  assert.throws(() => assertPublicKey(privateJwk), /private part/);
});

test('reports a file whose hash differs and a file that could not be downloaded', () => {
  const manifest = parseManifest(manifestBytes);
  assert.deepEqual(compareFiles(manifest.files, { 'loader.js': loader }), []);
  assert.deepEqual(compareFiles(manifest.files, { 'loader.js': Buffer.from('evil') }), [
    'loader.js: hash differs from the signed manifest',
  ]);
  assert.deepEqual(compareFiles(manifest.files, { 'loader.js': null }), ['loader.js: could not be downloaded']);
});

test('rejects unsafe file names and malformed hashes in the manifest', () => {
  const bad = (files) => Buffer.from(JSON.stringify({ version: '1', sequence: 1, issuedAt: 'x', files }));
  assert.throws(() => parseManifest(bad({ '../etc/passwd': sriSha384(loader) })), /unsafe file name/);
  assert.throws(() => parseManifest(bad({ 'loader.js': 'sha256-abc' })), /bad hash/);
  assert.throws(() => parseManifest(Buffer.from(JSON.stringify({ version: '1', sequence: 0, issuedAt: 'x', files: {} }))), /sequence/);
});

test('rejects a lower sequence (rollback to an older signed manifest)', () => {
  assert.equal(sequenceIsNotLower(5, 5), true);
  assert.equal(sequenceIsNotLower(5, 6), true);
  assert.equal(sequenceIsNotLower(5, 4), false);
});

/**
 * @module monitor
 * Command line run every five minutes by `.github/workflows/monitor.yml`: reads the signed manifest kept in this repository,
 * verifies its signature with the pinned public key, downloads each listed file from the CDN and compares its hash. Exits with 1
 * on any mismatch, so the heartbeat is not sent and the external monitor alerts. Prints only file names and reasons.
 * Until the first release publishes a manifest it reports "not armed" and exits 0 (stage E0).
 */
import { existsSync, readFileSync } from 'node:fs';
import { compareFiles, parseManifest, verifyManifestSignature } from './verify.mjs';

const MANIFEST = 'manifest/manifest.json';
const SIGNATURE = 'manifest/manifest.sig';
const PINNED_KEY = 'keys/manifest.pub.json';
const CDN_BASE = process.env.CDN_BASE ?? 'https://cdn.accesimas.cl/v1';
const TIMEOUT_MS = 20_000;

/**
 * Downloads one file, following no redirects: a redirect on the CDN is itself a change worth an alert.
 * @param {string} name - File name from the manifest.
 * @returns {Promise<Buffer|null>} The bytes, or null when the request failed or the status was not 200.
 */
async function download(name) {
  try {
    const response = await fetch(`${CDN_BASE}/${name}`, {
      redirect: 'error',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    return response.status === 200 ? Buffer.from(await response.arrayBuffer()) : null;
  } catch {
    return null;
  }
}

/** Runs the check and returns the process exit code. */
async function main() {
  if (!existsSync(MANIFEST)) {
    console.log('monitor: not armed (no manifest published yet)');
    return 0;
  }
  if (!existsSync(SIGNATURE) || !existsSync(PINNED_KEY)) {
    console.error('monitor: the manifest needs manifest.sig and the pinned public key');
    return 1;
  }
  const manifestBytes = readFileSync(MANIFEST);
  const publicJwk = JSON.parse(readFileSync(PINNED_KEY, 'utf8'));
  const signature = readFileSync(SIGNATURE, 'utf8');
  if (!(await verifyManifestSignature({ manifestBytes, signature, publicJwk }))) {
    console.error('monitor: the manifest signature is NOT valid for the pinned key');
    return 1;
  }
  const manifest = parseManifest(manifestBytes);
  const names = Object.keys(manifest.files);
  const downloaded = Object.fromEntries(await Promise.all(names.map(async (name) => [name, await download(name)])));
  const problems = compareFiles(manifest.files, downloaded);
  if (problems.length > 0) {
    for (const problem of problems) console.error(`monitor: ${problem}`);
    return 1;
  }
  console.log(`monitor: ${names.length} files match manifest ${manifest.version} (sequence ${manifest.sequence})`);
  return 0;
}

main().then(
  (code) => process.exit(code),
  (error) => {
    console.error(`monitor: ${error instanceof Error ? error.message : 'unexpected error'}`);
    process.exit(1);
  },
);

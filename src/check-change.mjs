/**
 * @module check-change
 * Run by the pull request checks when `manifest/` changes: the new manifest must carry a valid signature for the pinned key and its
 * sequence must not be lower than the one on the base branch (no rollback to an older signed manifest). Prints only reasons.
 * Usage: node src/check-change.mjs [path of the previous manifest.json]
 */
import { existsSync, readFileSync } from 'node:fs';
import { parseManifest, sequenceIsNotLower, verifyManifestSignature } from './verify.mjs';

const previousPath = process.argv[2];

/** Runs the check and returns the process exit code. */
async function main() {
  const manifestBytes = readFileSync('manifest/manifest.json');
  const signature = readFileSync('manifest/manifest.sig', 'utf8');
  const publicJwk = JSON.parse(readFileSync('keys/manifest.pub.json', 'utf8'));
  if (!(await verifyManifestSignature({ manifestBytes, signature, publicJwk }))) {
    console.error('check: the new manifest signature is NOT valid for the pinned key');
    return 1;
  }
  const next = parseManifest(manifestBytes);
  if (previousPath && existsSync(previousPath)) {
    const previous = parseManifest(readFileSync(previousPath));
    if (!sequenceIsNotLower(previous.sequence, next.sequence)) {
      console.error(`check: sequence ${next.sequence} is lower than the previous ${previous.sequence} (rollback)`);
      return 1;
    }
  }
  console.log(`check: manifest ${next.version}, sequence ${next.sequence}, signature valid`);
  return 0;
}

main().then(
  (code) => process.exit(code),
  (error) => {
    console.error(`check: ${error instanceof Error ? error.message : 'unexpected error'}`);
    process.exit(1);
  },
);

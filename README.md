# accesi-monitor

Public monitor of the Accesi+ accessibility widget. Every five minutes it checks that the files published on the CDN are exactly
the ones the last release signed, and sends a heartbeat to an external monitor only when they are. If the heartbeat stops, the
owner is alerted (email and phone).

This repository contains **only the monitor**: no product code, no customer data, no infrastructure. Its single secret is the
heartbeat URL (an Actions secret named `HEARTBEAT_URL`). It is public on purpose, so anyone can audit what is checked.

## How it works

1. A release of the product publishes `manifest/manifest.json` (file names and their SHA-384 hashes, a version and a growing
   `sequence`) and `manifest/manifest.sig` (ES256 signature, base64url of the raw `r‖s`) through a pull request to this repository.
   The key that signs it is a **different KMS key** from the one that signs customer configurations.
2. `keys/manifest.pub.json` holds the **pinned public key** (a P-256 JWK without `d`). Changing it is the way to make a forged manifest
   pass, so a pull request that touches `keys/` must wait 24 hours (`key-change-guard`) and a change that reaches `main` opens an issue
   (`key-change-alert.yml`), which notifies the owner by email and on the phone through the GitHub app.
3. `.github/workflows/monitor.yml` runs every five minutes: it verifies the signature, downloads every listed file from
   `https://cdn.accesimas.cl/v1/` (no redirects followed) and compares hashes. On any difference the job fails and **no heartbeat is sent**.
4. The external monitor (UptimeRobot) expects the heartbeat every five minutes with a 15 minute grace. A mismatch, a failed run, a
   skipped or delayed schedule and a schedule that GitHub disabled all end in the same alert.

Until the first release publishes a manifest the monitor reports "not armed" and exits successfully.

## Known limits

- GitHub can delay or skip scheduled runs, and disables them after 60 days without repository activity in a public repository. The
  detection objective is 15 minutes, with no guarantee. A release opens a pull request each time, which counts as activity.
- If the release job that signs the manifest is compromised it can sign a malicious manifest; the monitor cannot detect that (risk
  C-07 of the product threat model, accepted).

## Protection of `main`

`main` accepts changes only through pull requests with the checks `test`, `gitleaks`, `actionlint`, `zizmor`, `key-change-guard` and
`manifest-check` passing; no force push and no deletion. No reviewer approval is required because one person operates the project.

## Develop and test

```
npm test
```

No dependencies: only Node.js 24 built-ins. `npm run monitor` runs one check against the real CDN.

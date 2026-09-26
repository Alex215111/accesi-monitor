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
4. **What starts it:** an external cron (cron-job.org, every five minutes) calls the workflow's `workflow_dispatch` with a
   fine-grained token limited to this repository (`Actions: read and write`, 90 days, rotated by the owner). GitHub's own `schedule`
   is kept only as a **backup**, because it is not reliable (see below). A `concurrency` group keeps runs from overlapping.
5. The external monitor (Healthchecks.io) expects the heartbeat with a **period of 5 minutes and a grace of 10 minutes**, so the
   detection objective is **15 minutes (period + grace)**. A mismatch, a failed run, a trigger that never fired, an expired or stolen
   token and a disabled workflow all end in the same alert: no heartbeat.

Until the first release publishes a manifest the monitor reports "not armed" and exits successfully.

## Known limits

- GitHub's `schedule` is **not a usable trigger**: measured on this repository, `*/5` ran 4 times in about 13 hours, with gaps of
  2 h 24 min to 5 h 34 min. That is why an external cron starts the workflow and the `schedule` is only a backup. GitHub also disables
  scheduled workflows of a public repository after 60 days without activity; a release opens a pull request each time, which counts
  as activity.
- The trigger token could be stolen: it can start or disable the workflow, but it cannot send or fake the heartbeat (that URL is an
  Actions secret the token cannot read), so the worst case is the missing heartbeat, which alerts (risk C-08 of the product threat
  model). The token is rotated every 90 days.
- The objective is 15 minutes (period 5 + grace 10) once the external cron is running; it is a target, not a guarantee.
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

# Security and privacy

SiteWarden is built so that **nobody but you holds your credentials or your data**. There's no SiteWarden server: the app talks directly to the services you connect.

## What is stored where

| Data | Location | Protection |
|---|---|---|
| Domains, scan history, settings, Cloudflare change log | `%APPDATA%\sitewarden\sitewarden.db` (SQLite) | your OS account |
| API keys, Cloudflare token, agent and VM tokens, webhook URL | `%APPDATA%\sitewarden\sitewarden-keys.json` | each value encrypted with Electron `safeStorage` (Windows DPAPI, macOS Keychain, Linux libsecret). If OS encryption is unavailable, keys aren't saved. |
| Nuclei, templates, private Java | `%APPDATA%\sitewarden\tools\` | checksum-verified on download |
| Monitoring data (checks, scripts seen, CSP reports, alerts, VM results) | D1 database in **your** Cloudflare account | Cloudflare account security; read with the agent token |

Plaintext keys never reach the app's window (renderer): it only learns whether a key is set. The window runs sandboxed with context isolation, a strict Content-Security-Policy, and no navigation to other sites.

## What is sent to whom

| Destination | What | When |
|---|---|---|
| Your website | normal HTTPS requests (quick scan); thousands of requests (deep scan) | when you scan |
| Google Safe Browsing / VirusTotal / URLhaus | your domain name, with your key | quick scan, if keys are set; the agent, if copied |
| Cloudflare API | configuration calls with your token | Cloudflare page and Protection tab |
| Your agent Worker | desktop reads/writes with the agent token; browser guard reports (script URLs without query strings, CSP violations) | Protection tab; visitors' browsers if you add guard.js |
| GitHub / Adoptium | download requests for Nuclei, templates and Java | first launch, weekly template refresh |
| ProjectDiscovery interactsh | probe data | **only** if you enable out-of-band checks (off by default) |
| Slack / Discord | alert text | only if you set a webhook |

SiteWarden has no telemetry and no analytics.

## Tokens

| Token | Held by | Can do |
|---|---|---|
| Cloudflare API token | desktop (encrypted) | whatever permissions you gave it |
| Agent token (random, 256-bit) | desktop + Worker secret | read monitoring data, approve scripts, manage the VM schedule |
| VM token (random, 256-bit) | VM config (0600) + Worker secret | read the site list and schedule, upload results. **Can't** read monitoring data. |

Tokens are compared in constant time. Rotate the VM token from the Oracle agent page if the VM or its cloud-init leaks.

## Safety rails

- **Domain verification** (DNS TXT or meta tag) before any scan, Cloudflare change or agent coverage; re-checked every 30 days.
- The agent Worker accepts reports only for its configured sites and only from matching origins, and caps body sizes.
- Deep scans skip intrusive, denial-of-service, fuzzing, brute-force and default-login templates. ZAP runs passively only.
- Downloads are refused without a matching SHA-256. Archive extraction rejects path-traversal entries.
- Cloudflare changes are snapshotted and revertable, and never replace your existing rules.

## Limitations

- SiteWarden looks at your site from the **outside**. It doesn't inspect server files, so malware that isn't yet visible in pages can be missed.
- Free API tiers (Safe Browsing, VirusTotal) are licensed for non-commercial use. Check their terms for commercial sites.
- 0.1.0 installers aren't code-signed.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).

# Getting started

## 1. Install

Download `SiteWarden-Setup-<version>.exe` from [Releases](https://github.com/vivekchakraverty/sitewarden/releases) and run it. The installer is per-user and needs no administrator rights.

The 0.1.0 installer isn't code-signed. If Windows SmartScreen shows "Windows protected your PC", click **More info › Run anyway**. You can check the download against the SHA-256 listed on the release page:

```powershell
Get-FileHash .\SiteWarden-Setup-0.1.0.exe -Algorithm SHA256
```

### First launch

About 3 seconds after the first launch, SiteWarden starts setting up the deep-scan tools in the background:

| Tool | Source | Size | When |
|---|---|---|---|
| Nuclei | official GitHub release, verified against the release's `checksums.txt` | ~40 MB | always |
| Nuclei templates | `projectdiscovery/nuclei-templates` | ~14,000 small files | always, then refreshed weekly |
| Java 21 (Eclipse Temurin JRE) | Adoptium API, verified against its SHA-256 | ~45 MB | only if OWASP ZAP is installed and no Java 17+ is found |

A banner shows progress. You can keep using the app or click **Stop**. The first template download can take 10–15 minutes on Windows. To turn automatic setup off, go to **Deep scanners › Settings**.

OWASP ZAP itself isn't downloaded because it has its own installer. Get it from [zaproxy.org/download](https://www.zaproxy.org/download/) if you want ZAP baseline scans.

## 2. Add and verify a domain

Type your domain (for example `example.com`) in the sidebar and click **Add**. SiteWarden won't scan a domain until you prove you control it. Do **one** of these:

- **DNS TXT record** (recommended): at your DNS provider, add a TXT record on `example.com` (or on `_sitewarden.example.com`) with the value shown, such as `sitewarden-verification=3f2a…`.
- **Meta tag:** add `<meta name="sitewarden-verification" content="3f2a…">` to the `<head>` of your homepage.

Click **Verify**. DNS changes can take a few minutes to appear. Ownership is re-checked automatically every 30 days.

## 3. Add API keys (optional)

Under **API keys**, paste any of these free keys to turn on malware and blacklist checks:

| Key | Where to get it | Free limits |
|---|---|---|
| Google Safe Browsing | [Get started guide](https://developers.google.com/safe-browsing/v4/get-started): create a Google Cloud project, enable the Safe Browsing API, create an API key | free for non-commercial use |
| VirusTotal | [Sign up](https://www.virustotal.com/gui/join-us), then Profile › API key | about 4 lookups/minute, 500/day |
| abuse.ch (URLhaus) | [auth.abuse.ch](https://auth.abuse.ch/): generate an Auth-Key | free |

Keys are encrypted with your operating system's key store (Windows DPAPI or macOS Keychain) and are only ever sent to their own service.

## 4. Run a scan

Open the domain and click **Run scan**. A quick scan takes a few seconds and gives:

- a **grade** (A–F) and a **score** (0–100);
- **findings** sorted by severity. Click one to see why it matters and the exact fix for your platform;
- a **checks** table showing what ran, what was skipped and why.

**Export report** saves a standalone HTML report you can share.

For a deeper look, tick **Nuclei** and/or **ZAP baseline** before clicking **Run deep scan**. See [Scanning](scanning.md#deep-scanners).

## 5. Next steps

- [Connect Cloudflare](cloudflare.md) for DDoS protection, one-click hardening and 24/7 monitoring.
- [Set up the Oracle agent](oracle-agent.md) for scheduled deep scans while your computer is off.

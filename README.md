# SiteWarden

**A free desktop app that checks your website's security using your own free accounts and keys.**

SiteWarden checks a website you own for common security problems. It tells you in plain language what's wrong and gives you copy-paste fixes for Nginx, Apache, Cloudflare, WordPress and more. Each user brings their own API keys and accounts, so there is no SiteWarden server and no subscription, and nobody else holds your credentials.

> **Status: 0.1.0, early release.** It works end to end on Windows. The Cloudflare and Oracle features have been tested against mocked APIs but not yet against real accounts. Please [report issues](https://github.com/vivekchakraverty/sitewarden/issues).

## What it does

| Area | How |
|---|---|
| **Quick scan** (seconds) | HTTPS and certificates, security headers, cookie flags, outdated JavaScript libraries, mixed content, exposed files (`.git`, `.env`, backups, phpinfo), SPF/DMARC/CAA |
| **Malware and blacklists** | Google Safe Browsing, VirusTotal and URLhaus, with your own free keys |
| **Deep scan** (minutes) | [Nuclei](https://github.com/projectdiscovery/nuclei) with non-intrusive templates and an [OWASP ZAP](https://www.zaproxy.org/) baseline (crawl + passive), run on your computer |
| **Fix suggestions** | Every finding explains the risk and gives the exact config for your platform. Reports export to HTML. |
| **DDoS, WAF and bots** | Connect your free Cloudflare account. One-click, revertable hardening: HTTPS-only, TLS 1.2+, Bot Fight Mode, security headers, login rate limiting, HSTS |
| **24/7 monitoring** | Deploys a small Worker into *your* Cloudflare account. It checks uptime, blacklists and new third-party scripts (card-skimmer detection), collects CSP reports, and alerts you on Slack or Discord. |
| **Scheduled deep scans** | Optional agent on a free Oracle Cloud VM, set up by pasting one cloud-init script. It needs no open ports. |

SiteWarden only scans domains you've **proved you own** with a DNS TXT record or a meta tag.

## Install

1. Download `SiteWarden-Setup-0.1.0.exe` from the [latest release](https://github.com/vivekchakraverty/sitewarden/releases/latest).
2. Run it. The installer isn't code-signed yet, so Windows SmartScreen may warn you: choose **More info › Run anyway**.
3. On first launch, SiteWarden downloads the deep-scan tools in the background (about 85 MB, checksum-verified). You can stop this and install them later from **Deep scanners**.

macOS and Linux can run it from source (see [Development](docs/development.md)); packaged builds for them aren't published yet.

## Quick start

1. **Add your domain** in the sidebar, then add the DNS TXT record or meta tag it shows you and click **Verify**.
2. *(Optional)* Add free API keys under **API keys** for malware and blacklist checks.
3. Click **Run scan** and open each finding to see how to fix it.
4. *(Optional)* Tick **Nuclei** and **ZAP baseline** for a deep scan.
5. *(Optional)* Connect **Cloudflare** for protection and 24/7 monitoring, and the **Oracle agent** for scheduled deep scans.

## Documentation

- [Getting started](docs/getting-started.md): install, verify a domain, add keys, first scan
- [Scanning](docs/scanning.md): every check, how scoring works, the deep scanners
- [Cloudflare protection and monitoring](docs/cloudflare.md): API token, hardening, the agent Worker, guard.js and CSP
- [Oracle scan agent](docs/oracle-agent.md): scheduled deep scans from a free VM
- [Security and privacy](docs/security.md): what is stored where, what is sent to whom, the token model
- [Development](docs/development.md): architecture, tests, building and releasing
- [Changelog](CHANGELOG.md)

## Responsible use

Only scan sites you own or have written permission to test. Deep scans send thousands of requests, so your host or firewall may notice and rate-limit you. SiteWarden enforces domain verification and skips intrusive, denial-of-service and brute-force checks. A clean report doesn't guarantee a site is secure: SiteWarden looks at a site from the outside and doesn't replace a file-level malware scan or a professional penetration test.

## License

[MIT](LICENSE). Nuclei, OWASP ZAP and Eclipse Temurin are separate projects under their own licenses. SiteWarden downloads them from their official sources and doesn't bundle them.

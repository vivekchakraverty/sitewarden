# Scanning

Every scan requires a verified domain. Requests identify themselves with the User-Agent `SiteWarden/0.1 (owner-verified security self-scan)`.

## Quick checks

| Check | What it looks for | Typical fix |
|---|---|---|
| **HTTPS and certificate** | untrusted, expired or soon-to-expire certificate (< 14 days); TLS 1.0/1.1; HTTP not redirecting to HTTPS | Let's Encrypt or Cloudflare SSL; 301 redirect |
| **Security headers** | missing HSTS (or max-age < 6 months), CSP (or `'unsafe-inline'` scripts), `X-Content-Type-Options`, framing protection, `Referrer-Policy`, `Permissions-Policy`; `Server`/`X-Powered-By` version leaks | header config for Nginx, Apache or Cloudflare |
| **Cookie flags** | cookies without `Secure`, `SameSite`, or `HttpOnly` on session-like names | `Set-Cookie` attributes, PHP/Express settings |
| **Page content** | outdated jQuery (< 3.5), jQuery UI (< 1.13), Bootstrap, AngularJS 1.x, Lodash, Moment, Vue 2; mixed content; third-party scripts without Subresource Integrity; CMS generator tag; directory listing | update the library, use https:// URLs, add `integrity` |
| **Exposed files** | `/.git/HEAD`, `/.env`, `wp-config.php` backups, SQL dumps, `.htpasswd`, `phpinfo.php`, `/server-status`, `.DS_Store`; missing `security.txt` | delete the file, block dotfiles, rotate secrets |
| **DNS and email** | missing or weak SPF, missing DMARC or `p=none`, no CAA record | DNS records to add |
| **Google Safe Browsing** | malware, phishing or unwanted-software listing | cleanup steps and review request |
| **VirusTotal** | security vendors flagging the domain | cleanup and per-vendor re-review |
| **URLhaus** | live or past malware URLs on the host | take down files, close the entry point |

Exposed-file probes only report a hit when the response content matches the file type, so sites that return "200 OK" for every URL don't cause false alarms.

## Scoring

Each finding deducts points: critical 30, high 15, medium 7, low 2, info 0. The score starts at 100. Any critical finding means the grade is **F**; otherwise A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F below. The last 50 scans per domain are kept.

## Deep scanners

Set them up on the **Deep scanners** page (this happens automatically on first launch), then tick them next to **Run scan**. A progress bar shows live status and **Cancel scan** stops them.

### Nuclei

[Nuclei](https://github.com/projectdiscovery/nuclei) runs thousands of community templates for known CVEs, misconfigurations, exposed panels and files.

- **Never run:** templates tagged `dos`, `fuzz`, `fuzzing`, `intrusive`, `bruteforce`, `brute-force`, `default-login`, `osint`.
- Only `http`, `ssl` and `dns` protocols; severities low and above.
- **Out-of-band checks** (interactsh) are off by default because they send probe data through ProjectDiscovery's public servers. You can turn them on in Settings.
- Default rate is 20 requests/second with a 30-minute time limit. A small site needs about 10,000 requests, which takes about 12 minutes.

### OWASP ZAP baseline

[ZAP](https://www.zaproxy.org/) crawls the site for a few minutes (3 by default) and reports what its **passive** rules see in the responses: CORS misconfiguration, missing CSRF tokens, vulnerable JavaScript libraries, information leaks, cache problems. **It sends no attacks** (no active scan).

- It runs through ZAP's Automation Framework with a throwaway home folder and a random port, so your own ZAP setup isn't touched.
- ZAP alerts that duplicate the quick checks (headers, cookies, version leaks) are dropped.
- It needs Java 17+. SiteWarden finds an existing one (ZAP's installer config, `JAVA_HOME`, common JDK folders, `PATH`) or installs a private Temurin 21 that doesn't change your system Java.

Deep-scan findings show a `nuclei` or `zap` tag and include the scanner's own fix text and references.

## Reports

**Export report** writes a single HTML file with the grade, every finding with its fix, and the checks table. It contains no secrets.

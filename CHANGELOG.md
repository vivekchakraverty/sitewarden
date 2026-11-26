# Changelog

## 0.2.0 (2026-11-26)

### Added
- macOS (`.dmg` for Apple Silicon and Intel) and Linux (`.AppImage`, `.deb`) packages, built by CI on each OS.
- CI runs typecheck and tests on Windows, macOS and Linux, and packages all three. Tagged releases publish every installer with a `.sha256`.
- On macOS, uses the Java bundled with `ZAP.app` before downloading one.

### Fixed
- Nuclei and the private Java runtime are marked executable after extraction on macOS and Linux.
- On Linux without a keyring, keys are no longer stored with Electron's weak "basic_text" fallback; the app explains how to enable GNOME Keyring or KWallet instead.
- The keys file is written owner-only (0600).
- Only one copy of the app runs at a time.

## 0.1.0 (2026-11-26)

First public release.

### Scanning
- Domain ownership verification (DNS TXT or meta tag), re-checked every 30 days.
- Quick scan: HTTPS and certificates, security headers, cookie flags, outdated JS libraries, mixed content, Subresource Integrity, exposed sensitive files, SPF/DMARC/CAA.
- Malware and blacklist checks with your own keys: Google Safe Browsing, VirusTotal, URLhaus.
- Scores and grades, a fix library with platform-specific steps, HTML report export.
- Deep scans on this computer: Nuclei (non-intrusive templates) and OWASP ZAP baseline (spider + passive), with progress and cancel.
- First-launch setup downloads Nuclei, its templates and (when ZAP needs it) a private Java 21, all checksum-verified; templates refresh weekly.

### Cloudflare
- Connect your own Cloudflare account with a scoped API token.
- Revertable zone hardening: Always HTTPS, TLS 1.2+, HTTPS rewrites, Bot Fight Mode, security headers, CSP report-only, login rate limit, HSTS, SSL Full (strict).
- Monitoring agent Worker + D1 deployed into your account: uptime, new third-party script detection, Safe Browsing/URLhaus, CSP reports, Slack/Discord alerts.
- Optional `guard.js` browser script, with a live CSP compatibility check and a one-click Cloudflare fix.

### Oracle scan agent
- cloud-init for an Oracle Cloud Always Free VM (or any Linux + Docker) that runs scheduled Nuclei + ZAP scans and reports through your Worker. Outbound-only, with a separate limited token.

### Known limitations
- The Windows installer isn't code-signed; no macOS or Linux packages (added in 0.2.0).
- Cloudflare and Oracle features are tested against mocked APIs but not yet against live accounts.

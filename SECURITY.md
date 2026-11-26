# Security policy

## Supported versions

Only the latest release gets security fixes.

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Use GitHub's private reporting: **[Report a vulnerability](https://github.com/vivekchakraverty/sitewarden/security/advisories/new)**.

Please include the version, your OS, steps to reproduce and the impact. You'll get an acknowledgement within a week. Fixes are credited in the release notes unless you'd rather stay anonymous.

Especially welcome:
- ways to read or exfiltrate stored keys or tokens;
- bypasses of domain verification (scanning domains you don't control);
- ways for a web page, Worker response or scanner output to run code in the app;
- ways for the agent Worker or VM token to access more than documented in [docs/security.md](docs/security.md).

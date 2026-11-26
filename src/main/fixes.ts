// Fix library: plain-language reason plus copy-paste steps for common platforms.
import type { Fix } from '../shared/types'

const CF_HEADERS = 'Cloudflare dashboard > Rules > Transform Rules > Modify Response Header > Create rule > "Set static" header.'

export const FIXES: Record<string, Fix> = {
  'tls-certificate': {
    id: 'tls-certificate',
    title: 'Install a valid, auto-renewing TLS certificate',
    why: 'An invalid, expired or missing certificate makes browsers warn visitors away and leaves traffic unencrypted.',
    steps: [
      { platform: 'Cloudflare', text: 'Proxy the domain through Cloudflare (orange cloud). SSL/TLS > Overview: choose "Full (strict)". Cloudflare issues and renews the edge certificate for free.' },
      { platform: 'Let\'s Encrypt (Linux server)', code: 'sudo apt install certbot python3-certbot-nginx\nsudo certbot --nginx -d example.com -d www.example.com\n# renewal is installed as a systemd timer; test it:\nsudo certbot renew --dry-run' },
      { platform: 'Shared hosting / cPanel', text: 'Open SSL/TLS Status (or "AutoSSL") and run AutoSSL for the domain, or ask your host to enable free Let\'s Encrypt certificates.' }
    ],
    references: ['https://letsencrypt.org/getting-started/']
  },
  'tls-protocols': {
    id: 'tls-protocols',
    title: 'Allow only TLS 1.2 and 1.3',
    why: 'TLS 1.0/1.1 have known weaknesses and are rejected by modern browsers.',
    steps: [
      { platform: 'Nginx', code: 'ssl_protocols TLSv1.2 TLSv1.3;' },
      { platform: 'Apache', code: 'SSLProtocol -all +TLSv1.2 +TLSv1.3' },
      { platform: 'Cloudflare', text: 'SSL/TLS > Edge Certificates > Minimum TLS Version: TLS 1.2.' }
    ]
  },
  'https-redirect': {
    id: 'https-redirect',
    title: 'Redirect all HTTP traffic to HTTPS',
    why: 'Anything served over HTTP can be read or changed by anyone on the network.',
    steps: [
      { platform: 'Nginx', code: 'server {\n    listen 80;\n    server_name example.com www.example.com;\n    return 301 https://$host$request_uri;\n}' },
      { platform: 'Apache (.htaccess)', code: 'RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]' },
      { platform: 'Cloudflare', text: 'SSL/TLS > Edge Certificates > turn on "Always Use HTTPS".' }
    ]
  },
  'header-hsts': {
    id: 'header-hsts',
    title: 'Send a Strict-Transport-Security header',
    why: 'HSTS makes browsers refuse plain HTTP for your site, which blocks SSL-stripping attacks.',
    steps: [
      { platform: 'Nginx', code: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' },
      { platform: 'Apache', code: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"' },
      { platform: 'Cloudflare', text: 'SSL/TLS > Edge Certificates > HTTP Strict Transport Security (HSTS) > Enable. Start with a max-age of 6 months; only add includeSubDomains if every subdomain serves HTTPS.' }
    ],
    references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security']
  },
  'header-csp': {
    id: 'header-csp',
    title: 'Add a Content-Security-Policy',
    why: 'A CSP whitelists where scripts may load from, so injected scripts (XSS, card skimmers) are blocked.',
    steps: [
      { platform: 'Start in report-only mode', text: 'Deploy as Content-Security-Policy-Report-Only first, watch the browser console for a week, add the sources you actually use, then switch to the enforcing header.' },
      { platform: 'Nginx', code: "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; upgrade-insecure-requests\" always;" },
      { platform: 'Apache', code: "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; upgrade-insecure-requests\"" },
      { platform: 'Cloudflare', text: `${CF_HEADERS} Header name: Content-Security-Policy.` },
      { platform: 'Static HTML (fallback)', code: "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'\">" }
    ],
    references: ['https://developer.mozilla.org/docs/Web/HTTP/CSP', 'https://csp-evaluator.withgoogle.com/']
  },
  'header-nosniff': {
    id: 'header-nosniff',
    title: 'Send X-Content-Type-Options: nosniff',
    why: 'Stops browsers from treating uploaded files as scripts.',
    steps: [
      { platform: 'Nginx', code: 'add_header X-Content-Type-Options "nosniff" always;' },
      { platform: 'Apache', code: 'Header always set X-Content-Type-Options "nosniff"' },
      { platform: 'Cloudflare', text: `${CF_HEADERS} Header name: X-Content-Type-Options, value: nosniff.` }
    ]
  },
  'header-framing': {
    id: 'header-framing',
    title: 'Prevent other sites from framing your pages',
    why: 'Clickjacking hides your page inside an invisible frame and tricks users into clicking buttons.',
    steps: [
      { platform: 'Nginx', code: 'add_header X-Frame-Options "SAMEORIGIN" always;\n# or, in your CSP: frame-ancestors \'self\';' },
      { platform: 'Apache', code: 'Header always set X-Frame-Options "SAMEORIGIN"' },
      { platform: 'Cloudflare', text: `${CF_HEADERS} Header name: X-Frame-Options, value: SAMEORIGIN.` }
    ]
  },
  'header-referrer': {
    id: 'header-referrer',
    title: 'Set a Referrer-Policy',
    why: 'Limits how much of your URLs is shared with other sites.',
    steps: [
      { platform: 'Nginx', code: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;' },
      { platform: 'Apache', code: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"' },
      { platform: 'HTML', code: '<meta name="referrer" content="strict-origin-when-cross-origin">' }
    ]
  },
  'header-permissions': {
    id: 'header-permissions',
    title: 'Set a Permissions-Policy',
    why: 'Turns off powerful browser features you do not use, so embedded or injected code cannot use them.',
    steps: [
      { platform: 'Nginx', code: 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;' },
      { platform: 'Apache', code: 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"' }
    ]
  },
  'hide-versions': {
    id: 'hide-versions',
    title: 'Stop advertising server software versions',
    why: 'Version strings let attackers look up exploits for your exact software.',
    steps: [
      { platform: 'Nginx', code: 'server_tokens off;' },
      { platform: 'Apache', code: 'ServerTokens Prod\nServerSignature Off\nHeader always unset X-Powered-By' },
      { platform: 'PHP (php.ini)', code: 'expose_php = Off' },
      { platform: 'Express (Node)', code: "app.disable('x-powered-by')" }
    ]
  },
  'cookie-flags': {
    id: 'cookie-flags',
    title: 'Set Secure, HttpOnly and SameSite on cookies',
    why: 'Secure keeps cookies off HTTP, HttpOnly hides session cookies from scripts (XSS), SameSite blocks cross-site request forgery.',
    steps: [
      { platform: 'Set-Cookie header', code: 'Set-Cookie: session=...; Path=/; Secure; HttpOnly; SameSite=Lax' },
      { platform: 'PHP (php.ini)', code: 'session.cookie_secure = 1\nsession.cookie_httponly = 1\nsession.cookie_samesite = "Lax"' },
      { platform: 'Express (Node)', code: "res.cookie('session', value, { secure: true, httpOnly: true, sameSite: 'lax' })" }
    ]
  },
  'update-js-library': {
    id: 'update-js-library',
    title: 'Update the outdated JavaScript library',
    why: 'Old library versions have published exploits that work on any site using them.',
    steps: [
      { platform: 'npm project', code: 'npm install jquery@latest   # replace with the library named in the finding\nnpm audit' },
      { platform: 'CDN link', text: 'Change the version in the <script src> URL to the latest release and test the pages that use it.' },
      { platform: 'WordPress', text: 'Update WordPress core, the theme and plugins. Old jQuery usually comes from an outdated theme or a plugin that bundles its own copy.' }
    ]
  },
  'mixed-content': {
    id: 'mixed-content',
    title: 'Load every resource over HTTPS',
    why: 'Resources loaded over HTTP can be replaced in transit, and browsers block or warn about them.',
    steps: [
      { platform: 'Code', text: 'Change http:// URLs in your templates to https:// (or to relative paths like /img/logo.png).' },
      { platform: 'Any server (CSP)', code: 'Content-Security-Policy: upgrade-insecure-requests' },
      { platform: 'Cloudflare', text: 'SSL/TLS > Edge Certificates > turn on "Automatic HTTPS Rewrites".' },
      { platform: 'WordPress', text: 'Settings > General: make both URLs https://, then run a search-replace of http://yourdomain to https://yourdomain in the database (e.g. with WP-CLI: wp search-replace).' }
    ]
  },
  sri: {
    id: 'sri',
    title: 'Add Subresource Integrity to third-party scripts',
    why: 'SRI makes the browser refuse a CDN file if its contents change, so a compromised CDN cannot run code on your site.',
    steps: [
      { platform: 'HTML', code: '<script src="https://cdn.example.com/lib@1.2.3/lib.min.js"\n        integrity="sha384-..." crossorigin="anonymous"></script>' },
      { platform: 'Generate the hash', code: 'curl -s https://cdn.example.com/lib@1.2.3/lib.min.js | openssl dgst -sha384 -binary | openssl base64 -A' },
      { platform: 'Note', text: 'Only use SRI with version-pinned URLs. Tag managers and analytics scripts change constantly; restrict those with CSP instead.' }
    ],
    references: ['https://www.srihash.org/']
  },
  'hide-generator': {
    id: 'hide-generator',
    title: 'Remove the generator meta tag',
    why: 'It tells attackers which CMS and version to target.',
    steps: [
      { platform: 'WordPress (functions.php)', code: "remove_action('wp_head', 'wp_generator');\nadd_filter('the_generator', '__return_empty_string');" },
      { platform: 'Other CMS', text: 'Look for a "show generator / version" option in the SEO or head settings, or remove the tag from the theme\'s header template. Keeping the CMS updated matters more than hiding it.' }
    ]
  },
  'directory-listing': {
    id: 'directory-listing',
    title: 'Turn off directory listing',
    why: 'Directory listings expose every file in a folder, including backups and private uploads.',
    steps: [
      { platform: 'Nginx', code: 'autoindex off;' },
      { platform: 'Apache (.htaccess)', code: 'Options -Indexes' },
      { platform: 'Any host', text: 'Add an empty index.html to the folder as a stopgap.' }
    ]
  },
  'block-dotfiles': {
    id: 'block-dotfiles',
    title: 'Block access to hidden files and remove them from the web root',
    why: 'Files like .git, .env and .htpasswd hold source code and secrets. Assume anything exposed is already copied: rotate the secrets.',
    steps: [
      { platform: 'First', text: 'Delete the file from the public folder (or deploy so it is never copied there). Then change every password, API key and token it contained.' },
      { platform: 'Nginx', code: 'location ~ /\\.(?!well-known) {\n    deny all;\n    return 404;\n}' },
      { platform: 'Apache (.htaccess)', code: '<FilesMatch "^\\.">\n    Require all denied\n</FilesMatch>\nRedirectMatch 404 /\\.git' },
      { platform: 'Cloudflare', text: 'Security > WAF > Custom rules: block when URI Path contains "/.git" or "/.env".' }
    ]
  },
  'remove-backups': {
    id: 'remove-backups',
    title: 'Remove backup and dump files from the web root',
    why: 'Backups contain credentials and user data and are a common way sites get breached.',
    steps: [
      { platform: 'First', text: 'Delete the file, then rotate the database password and any keys it contained. Keep backups outside the public folder or in private storage.' },
      { platform: 'Nginx', code: 'location ~* \\.(bak|sql|old|orig|swp|tar|gz|zip)$ {\n    deny all;\n    return 404;\n}' },
      { platform: 'Apache (.htaccess)', code: '<FilesMatch "\\.(bak|sql|old|orig|swp|tar|gz|zip)$|~$">\n    Require all denied\n</FilesMatch>' }
    ]
  },
  'remove-debug-pages': {
    id: 'remove-debug-pages',
    title: 'Remove debug and status pages',
    why: 'phpinfo and server-status pages give attackers a map of your server.',
    steps: [
      { platform: 'phpinfo', text: 'Delete phpinfo.php / info.php from the server.' },
      { platform: 'Apache server-status', code: '<Location "/server-status">\n    SetHandler server-status\n    Require local\n</Location>' }
    ]
  },
  'security-txt': {
    id: 'security-txt',
    title: 'Publish a security.txt',
    why: 'Gives security researchers a clear way to report problems to you instead of disclosing them publicly.',
    steps: [
      { platform: '/.well-known/security.txt', code: 'Contact: mailto:security@example.com\nExpires: 2027-12-31T23:59:59Z\nPreferred-Languages: en' }
    ],
    references: ['https://securitytxt.org/']
  },
  'dns-spf': {
    id: 'dns-spf',
    title: 'Publish a strict SPF record',
    why: 'SPF lists the servers allowed to send mail for your domain, which makes spoofing harder.',
    steps: [
      { platform: 'Domain sends mail (example: Google Workspace)', code: 'TXT  @  "v=spf1 include:_spf.google.com -all"' },
      { platform: 'Domain never sends mail', code: 'TXT  @  "v=spf1 -all"' },
      { platform: 'Note', text: 'Include every service that sends as you (mail host, newsletter tool, CRM). Use ~all while testing, then -all.' }
    ]
  },
  'dns-dmarc': {
    id: 'dns-dmarc',
    title: 'Publish a DMARC policy',
    why: 'DMARC tells receiving servers to reject mail that fails SPF/DKIM and sends you reports about spoofing attempts.',
    steps: [
      { platform: 'Step 1: monitor', code: 'TXT  _dmarc  "v=DMARC1; p=none; rua=mailto:dmarc@example.com"' },
      { platform: 'Step 2: enforce (after reports look clean)', code: 'TXT  _dmarc  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"' },
      { platform: 'Domain never sends mail', code: 'TXT  _dmarc  "v=DMARC1; p=reject;"' }
    ]
  },
  'dns-caa': {
    id: 'dns-caa',
    title: 'Add a CAA record',
    why: 'CAA stops other certificate authorities from issuing certificates for your domain.',
    steps: [
      { platform: 'Let\'s Encrypt', code: 'CAA  @  0 issue "letsencrypt.org"' },
      { platform: 'Cloudflare-proxied', text: 'Cloudflare adds the CAA records it needs automatically when Universal SSL is on. Add your own only for other CAs you use.' }
    ]
  },
  'malware-cleanup': {
    id: 'malware-cleanup',
    title: 'Clean up a compromised site',
    why: 'Blacklisting means the site is (or recently was) serving malware or phishing. Visitors see warnings and search rankings drop.',
    steps: [
      { platform: '1. Contain', text: 'Put the site in maintenance mode or behind a login. Take a full backup of files and database for investigation.' },
      { platform: '2. Find the infection', text: 'Compare files against a clean copy or your Git repo. Look for recently modified files, unknown admin users, obfuscated PHP/JS (eval, base64_decode, atob) and injected <script> tags.' },
      { platform: '3. Close the hole', text: 'Update the CMS, themes and plugins; remove unused ones. Change all passwords (hosting, FTP/SSH, database, CMS admins) and rotate API keys.' },
      { platform: '4. Request review', text: 'Google: Search Console > Security issues > Request review. VirusTotal: contact each flagging vendor (links on the VirusTotal page). URLhaus: report the cleanup on the URL entry.' }
    ],
    references: ['https://developers.google.com/search/docs/monitor-debug/security/hacked']
  }
}

export function getFix(id: string): Fix | null {
  return FIXES[id] ?? null
}

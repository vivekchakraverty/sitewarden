# Cloudflare protection and monitoring

DDoS protection, a web application firewall and bot blocking can't come from code on your site. They come from putting the site behind a proxy. Cloudflare's **free plan** does this, and SiteWarden uses **your** Cloudflare account to configure it.

## 1. Create an API token

In Cloudflare go to **My Profile › API Tokens › Create Token › Create Custom Token**, and add:

| Scope | Permission | Access | Used for |
|---|---|---|---|
| Account | Workers Scripts | Edit | deploying the monitoring agent |
| Account | D1 | Edit | the agent's database |
| Zone | Zone | Read | finding your site's zone |
| Zone | Zone Settings | Edit | HTTPS, TLS, HSTS, SSL mode |
| Zone | Transform Rules | Edit | security-header and CSP rules |
| Zone | Zone WAF | Edit | login rate limit |
| Zone | Bot Management | Edit | Bot Fight Mode |

You can limit **Zone Resources** to the sites you add to SiteWarden. If a permission is missing, only the features that need it are disabled. Paste the token on the **Cloudflare** page and click **Connect**.

## 2. Harden each site

Open a domain › **Protection**. SiteWarden reads the current value of each setting:

| Setting | Pre-selected | Notes |
|---|---|---|
| Always use HTTPS | ✓ | |
| Minimum TLS 1.2 | ✓ | |
| Automatic HTTPS rewrites | ✓ | fixes mixed content |
| Bot Fight Mode | ✓ | may challenge legitimate bots (uptime monitors, webhooks) |
| Security headers rule | ✓ | `X-Content-Type-Options`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy`, `Permissions-Policy` |
| CSP in report-only mode | | needs the agent; each report is one Worker request |
| Rate-limit login pages | | 5 POSTs / 10 s on common login paths; the free plan allows only one rate-limit rule |
| HSTS (6 months) | | hard to undo: browsers remember it |
| SSL mode Full (strict) | | causes error 526 if your server's certificate is invalid |

Every change is recorded with its previous value and can be **reverted** from the change history. Rules are added one at a time with `sitewarden_*` refs, so your existing Cloudflare rules are never replaced.

## 3. Deploy the monitoring agent

On the **Cloudflare** page, click **Deploy agent**. SiteWarden uploads a Worker named `sitewarden-agent` and a D1 database named `sitewarden-agent` into **your** account, published at `https://sitewarden-agent.<your-subdomain>.workers.dev`. If your account has no workers.dev subdomain yet, open **Workers & Pages** in the Cloudflare dashboard once to choose one.

Every 30 minutes the agent:

- checks uptime and alerts after two failures in a row (and again when the site recovers);
- watches your homepage for **new third-party scripts**, the most common sign of an injected card skimmer;
- checks Google Safe Browsing and URLhaus, if you chose to copy those keys into the Worker (stored as encrypted Worker secrets).

Optional alerts go to a Slack or Discord incoming webhook. Data is kept for 30 days (checks, CSP reports) or 90 days (alerts). Everything fits the free plan (100,000 Worker requests a day).

**Redeploy after adding or verifying a domain** so the agent covers it.

## 4. Browser guard (optional)

The Protection tab gives you one line to add to every page:

```html
<script src="https://sitewarden-agent.<sub>.workers.dev/guard.js?site=example.com" async></script>
```

It watches which scripts actually run in visitors' browsers, including ones injected at runtime by tag managers, plugins or attackers. It samples 10% of page views and reports only script URLs without query strings, plus CSP violations. It never sends cookies, form data or personal information. New scripts appear on the Protection tab, where you approve the ones you expect.

### If your site has a Content-Security-Policy

The Protection tab checks your live policy:

- **Ready:** there's no CSP, or it already allows the agent.
- **Blocked:** it shows which directive blocks the guard and gives your policy with only the agent's address added, ready to paste into Nginx, Apache, a plugin panel or your meta tag.
- **Fix with Cloudflare:** when your policy is a static header (no per-request nonce and no blocking meta tag), one click makes Cloudflare send the updated policy. It can be reverted from the change history. If pages use different policies, update them on your server instead.
- **`'strict-dynamic'` policies** need the guard tag to carry your page's nonce. The tab shows the tag with a nonce placeholder.

## Removing everything

**Remove agent** deletes the Worker. The D1 database is kept so your history isn't lost; delete it in the Cloudflare dashboard if you want it gone. **Disconnect** forgets the token on this computer. To undo hardening, use **Revert** in each domain's change history.

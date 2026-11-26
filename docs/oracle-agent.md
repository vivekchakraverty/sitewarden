# Oracle scan agent

Runs the deep scanners (Nuclei and the ZAP baseline) on a schedule from a free **Oracle Cloud Always Free** VM, so your sites are scanned from a server even when your computer is off. Any Linux server with Docker works too.

## How it works

```
 Oracle VM (agent.py, every 10 min)          Your Cloudflare Worker            SiteWarden desktop
 ───────────────────────────────            ─────────────────────            ──────────────────
 GET  /api/vm/config  ───────────────────▶  sites, schedule, queued jobs
 docker run nuclei / zap-stable
 POST /api/vm/result  ───────────────────▶  stores raw output (D1)  ◀──────  GET /api/vm/results
                                            alerts on high/critical          parses into scan history
```

- **No inbound ports.** The VM only makes outbound HTTPS requests. The [Cloudflare agent](cloudflare.md#3-deploy-the-monitoring-agent) is its mailbox, so deploy that first.
- **A separate VM token.** It can read the site list and schedule and upload results, nothing else. It can't read your monitoring data, and the desktop's token can't post as the VM.
- **Same parsers as the desktop.** The VM uploads raw Nuclei JSONL and the ZAP JSON report. The app parses them exactly like local deep scans and adds them to each domain's history, marked **Oracle VM**.
- **Alerts.** Scans with high or critical issues raise an alert (and go to your Slack or Discord webhook).

## Setup

1. On the **Oracle agent** page, click **Set up the VM agent**. This creates the VM token and redeploys your Cloudflare agent with it.
2. Click **Copy cloud-init** (or **Save as file…**). The script contains the token, so treat it like a password.
3. In the [Oracle Cloud console](https://cloud.oracle.com/): **Compute › Instances › Create instance**
   - **Image:** Canonical Ubuntu 24.04 (22.04 also works)
   - **Shape:** Ampere `VM.Standard.A1.Flex`, 1 OCPU, 6 GB (Always Free eligible). If there's no capacity, try another availability domain or try later.
   - **Networking:** defaults. No ports need opening; you can remove the SSH rule if you never log in.
   - **Advanced options › Management › Initialization script:** paste the cloud-init.
4. Click **Create**. After about 5 minutes the status turns **online**. The first scan starts within 10 minutes and takes 15–30 minutes per site.

On a verified domain's Scan tab, **Scan on Oracle VM** queues an immediate scan.

## What cloud-init installs

| Item | Path |
|---|---|
| Docker (`docker.io`) and Python 3 | packages |
| `projectdiscovery/nuclei:latest`, `zaproxy/zap-stable` | Docker images, re-pulled daily |
| Agent (Python standard library only) | `/opt/sitewarden/agent.py` |
| Config (Worker URL + token, mode 0600) | `/etc/sitewarden/agent.json` |
| State and Nuclei templates | `/var/lib/sitewarden/` |
| Timer (every 10 min) and service | `sitewarden-agent.timer`, `sitewarden-agent.service` |
| Helper | `/usr/local/bin/sitewarden-agent` |

Containers run with `--network host` and a 2 GB memory limit. Host networking avoids the FORWARD-chain REJECT rule on Oracle's Ubuntu images, and nothing listens publicly.

## Schedule and limits

Set on the Oracle agent page and picked up at the VM's next check-in: scan interval per site (default 24 h), Nuclei rate and time limit, ZAP crawl time, and out-of-band checks (off). Values are clamped on the Worker and again on the VM.

## Troubleshooting

SSH in as `ubuntu` with the key Oracle gave you:

```bash
systemctl list-timers sitewarden-agent.timer      # next run
journalctl -u sitewarden-agent -n 50 --no-pager    # agent log
sudo systemctl start sitewarden-agent              # run now
cloud-init status --long                           # did setup finish?
```

| Symptom | Fix |
|---|---|
| "config request rejected (401)" in the log | The token was rotated: `sudo sitewarden-agent set-token <new token>` (the app shows this command) |
| Status stays "waiting for VM" | Check `cloud-init status --long`; image pulls can take a few minutes on first boot |
| ZAP fails on a 1 GB VM | Use the A1 shape with 6 GB; ZAP needs about 1–2 GB |

## Rotating the token

**Rotate VM token** redeploys the Worker with a new token; the old one stops working immediately. Run the command shown on the VM, or create new VMs with the refreshed cloud-init.

## Removing it

Terminate the instance in the Oracle console. Then remove the agent's token by rotating it, or redeploy the Cloudflare agent after resetting the app.

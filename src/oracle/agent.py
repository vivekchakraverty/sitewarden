#!/usr/bin/env python3
"""SiteWarden scan agent for an Oracle Cloud Always Free VM (or any Linux box with Docker).

Runs from a systemd timer every 10 minutes. Each run it:
  1. fetches its config (verified sites, schedule, limits) from the user's SiteWarden Cloudflare Worker
  2. picks one site that is due (a queued "scan now" job first, then the oldest scheduled one)
  3. runs Nuclei (non-intrusive templates) and an OWASP ZAP baseline (spider + passive) in Docker
  4. uploads the raw results to the Worker, where the desktop app fetches and parses them

Outbound HTTPS only; nothing listens on the network. Standard library only.
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

VERSION = "0.4.0"
CONF = os.environ.get("SITEWARDEN_CONF", "/etc/sitewarden/agent.json")
STATE_DIR = os.environ.get("SITEWARDEN_STATE", "/var/lib/sitewarden")
DOCKER = json.loads(os.environ.get("SITEWARDEN_DOCKER_CMD", '["docker"]'))
NUCLEI_IMAGE = "projectdiscovery/nuclei:latest"
ZAP_IMAGE = "zaproxy/zap-stable"
EXCLUDED_TAGS = "dos,fuzz,fuzzing,intrusive,bruteforce,brute-force,default-login,osint"
MAX_FIELD = 1_500_000  # bytes per uploaded result field
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")
UA = "SiteWarden-VM-Agent/" + VERSION


def log(msg):
    print(time.strftime("%Y-%m-%dT%H:%M:%S"), msg, flush=True)


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def api(conf, method, path, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        conf["worker"].rstrip("/") + path,
        data=data,
        method=method,
        headers={"Authorization": "Bearer " + conf["token"], "Content-Type": "application/json", "User-Agent": UA},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "{}")


def clamp(v, lo, hi, default):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def safe_settings(raw):
    raw = raw or {}
    return {
        "enabled": raw.get("enabled", True) is not False,
        "intervalHours": clamp(raw.get("intervalHours"), 1, 24 * 30, 24),
        "nucleiRate": clamp(raw.get("nucleiRate"), 1, 150, 20),
        "nucleiMaxMinutes": clamp(raw.get("nucleiMaxMinutes"), 2, 180, 30),
        "nucleiInteractsh": raw.get("nucleiInteractsh") is True,
        "zapSpiderMinutes": clamp(raw.get("zapSpiderMinutes"), 1, 30, 3),
        "zapMaxMinutes": clamp(raw.get("zapMaxMinutes"), 3, 120, 15),
    }


def docker(args, timeout, capture=True):
    try:
        p = subprocess.run(DOCKER + args, capture_output=capture, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        return -1, out, "timed out"


def update_images_and_templates(state):
    """Once a day: pull the latest images and Nuclei templates."""
    if time.time() - state.get("updatedAt", 0) < 24 * 3600:
        return
    for image in (NUCLEI_IMAGE, ZAP_IMAGE):
        code, _, err = docker(["pull", "-q", image], timeout=1800)
        if code != 0:
            log("pull failed for %s: %s" % (image, err.strip()[:300]))
    code, _, err = docker(nuclei_base() + ["-ut", "-nc", "-duc"], timeout=1800)
    if code != 0:
        log("template update failed: " + err.strip()[:300])
    state["updatedAt"] = time.time()


def nuclei_base():
    tdir = os.path.join(STATE_DIR, "nuclei-templates")
    cdir = os.path.join(STATE_DIR, "nuclei-config")
    os.makedirs(tdir, exist_ok=True)
    os.makedirs(cdir, exist_ok=True)
    return ["run", "--rm", "--network", "host", "--memory", "2g",
            "-v", tdir + ":/root/nuclei-templates",
            "-v", cdir + ":/root/.config/nuclei",
            NUCLEI_IMAGE]


def run_nuclei(host, s):
    args = nuclei_base() + [
        "-u", "https://" + host,
        "-jsonl", "-or", "-silent", "-nc", "-duc",
        "-severity", "low,medium,high,critical",
        "-etags", EXCLUDED_TAGS,
        "-pt", "http,ssl,dns",
        "-rl", str(s["nucleiRate"]), "-c", "10", "-timeout", "10", "-retries", "1",
        "-H", "User-Agent: " + UA + " nuclei",
    ]
    if not s["nucleiInteractsh"]:
        args.append("-ni")
    code, out, err = docker(args, timeout=s["nucleiMaxMinutes"] * 60)
    error = None
    if code != 0 and not out.strip():
        error = "nuclei exit %s: %s" % (code, err.strip()[-300:])
    return out[:MAX_FIELD], error


def zap_plan(host, spider_minutes):
    esc = re.escape(host)
    return {
        "env": {
            "contexts": [{"name": "target", "urls": ["https://%s/" % host], "includePaths": ["https?://(www\\.)?%s([/?#:].*)?" % esc]}],
            "parameters": {"failOnError": False, "failOnWarning": False, "progressToStdout": True},
        },
        "jobs": [
            {"type": "passiveScan-config", "parameters": {"maxAlertsPerRule": 10, "scanOnlyInScope": True}},
            {"type": "spider", "parameters": {"context": "target", "maxDuration": spider_minutes, "maxDepth": 5, "maxChildren": 30}},
            {"type": "passiveScan-wait", "parameters": {"maxDuration": 5}},
            {
                "type": "report",
                "parameters": {"template": "traditional-json", "reportDir": "/zap/wrk", "reportFile": "zap-report"},
                "risks": ["info", "low", "medium", "high"],
                "confidences": ["low", "medium", "high", "confirmed"],
            },
        ],
    }


def run_zap(host, s):
    work = tempfile.mkdtemp(prefix="sitewarden-zap-")
    try:
        os.chmod(work, 0o777)  # the ZAP image runs as user "zap"
        with open(os.path.join(work, "plan.yaml"), "w", encoding="utf-8") as f:
            json.dump(zap_plan(host, s["zapSpiderMinutes"]), f)  # JSON is valid YAML
        code, out, err = docker(
            ["run", "--rm", "--network", "host", "--memory", "2g", "-v", work + ":/zap/wrk:rw", ZAP_IMAGE,
             "zap.sh", "-cmd", "-silent", "-config", "connection.defaultUserAgent=" + UA + " zap", "-autorun", "/zap/wrk/plan.yaml"],
            timeout=s["zapMaxMinutes"] * 60,
        )
        report = os.path.join(work, "zap-report.json")
        if os.path.exists(report):
            with open(report, encoding="utf-8") as f:
                return f.read()[:MAX_FIELD], None
        return "", "zap exit %s, no report: %s" % (code, (out + err).strip()[-300:])
    finally:
        shutil.rmtree(work, ignore_errors=True)


def pick_site(cfg, state):
    sites = [h for h in cfg.get("sites", []) if isinstance(h, str) and HOST_RE.match(h)]
    for job in cfg.get("jobs", []):
        if job.get("site") in sites:
            return job["site"], job.get("id")
    s = cfg["settings"]
    if not s["enabled"]:
        return None, None
    due = [(state.get("last", {}).get(h, 0), h) for h in sites]
    due = [d for d in due if time.time() - d[0] >= s["intervalHours"] * 3600]
    if not due:
        return None, None
    return min(due)[1], None


def heartbeat(conf, extra=None):
    total, used, free = shutil.disk_usage(STATE_DIR if os.path.isdir(STATE_DIR) else "/")
    body = {"hostname": socket.gethostname(), "agentVersion": VERSION, "diskFreeGb": round(free / 1e9, 1)}
    body.update(extra or {})
    try:
        api(conf, "POST", "/api/vm/heartbeat", body)
    except (urllib.error.URLError, OSError, ValueError) as e:
        log("heartbeat failed: %s" % e)


def main():
    conf = load_json(CONF, None)
    if not conf or "worker" not in conf or "token" not in conf:
        log("missing config at " + CONF)
        return 2
    os.makedirs(STATE_DIR, exist_ok=True)
    state_path = os.path.join(STATE_DIR, "state.json")
    state = load_json(state_path, {})

    try:
        cfg = api(conf, "GET", "/api/vm/config")
    except urllib.error.HTTPError as e:
        log("config request rejected (%s). Was the token rotated? Update it with: sudo sitewarden-agent set-token <token>" % e.code)
        return 1
    except (urllib.error.URLError, OSError, ValueError) as e:
        log("config request failed: %s" % e)
        return 1
    cfg["settings"] = safe_settings(cfg.get("settings"))

    heartbeat(conf, {"state": "idle"})
    update_images_and_templates(state)
    save_json(state_path, state)

    site, job_id = pick_site(cfg, state)
    if not site:
        log("nothing due")
        return 0

    log("scanning %s%s" % (site, " (requested)" if job_id else ""))
    heartbeat(conf, {"state": "scanning", "site": site})
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    nuclei_out, nuclei_err = run_nuclei(site, cfg["settings"])
    zap_out, zap_err = run_zap(site, cfg["settings"])
    finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    result = {
        "site": site,
        "jobId": job_id,
        "startedAt": started,
        "finishedAt": finished,
        "nuclei": nuclei_out,
        "zap": zap_out,
        "errors": [e for e in (nuclei_err, zap_err) if e],
        "agentVersion": VERSION,
    }
    try:
        api(conf, "POST", "/api/vm/result", result, timeout=120)
    except (urllib.error.URLError, OSError, ValueError) as e:
        log("upload failed, will rescan next time: %s" % e)
        return 1
    state.setdefault("last", {})[site] = time.time()
    save_json(state_path, state)
    heartbeat(conf, {"state": "idle", "lastScan": site})
    log("done %s (%d nuclei lines, zap %s)" % (site, nuclei_out.count("\n"), "ok" if zap_out else "failed"))
    return 0


def set_token(token):
    conf = load_json(CONF, None)
    if not conf:
        print("no config at " + CONF)
        return 2
    if not re.match(r"^[A-Za-z0-9_-]{20,}$", token):
        print("that does not look like a SiteWarden VM token")
        return 2
    conf["token"] = token
    save_json(CONF, conf)
    os.chmod(CONF, 0o600)
    print("token updated")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "set-token":
        sys.exit(set_token(sys.argv[2]))
    sys.exit(main())

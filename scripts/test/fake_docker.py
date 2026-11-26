"""Stands in for `docker` in the VM agent test: records calls and emits canned Nuclei / ZAP output."""
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["FAKE_DOCKER_LOG"], "a", encoding="utf-8") as f:
    f.write(json.dumps(args) + "\n")

if args[:1] == ["pull"]:
    sys.exit(0)

if "projectdiscovery/nuclei:latest" in args:
    if "-ut" in args:
        sys.exit(0)
    print(json.dumps({"template-id": "git-config", "info": {"name": "Git Configuration - Detect", "severity": "medium", "remediation": "Block /.git"}, "matched-at": "https://mysite.com/.git/config"}))
    print(json.dumps({"template-id": "generic-env", "info": {"name": "Generic Env File Disclosure", "severity": "high"}, "matched-at": "https://mysite.com/.env"}))
    sys.exit(0)

if "zaproxy/zap-stable" in args:
    mount = args[args.index("-v") + 1]
    host_dir = mount.rsplit(":/zap/wrk", 1)[0]
    plan = json.load(open(os.path.join(host_dir, "plan.yaml"), encoding="utf-8"))
    assert [j["type"] for j in plan["jobs"]] == ["passiveScan-config", "spider", "passiveScan-wait", "report"], plan
    report = {"site": [{"alerts": [{"pluginid": "10098", "alert": "Cross-Domain Misconfiguration", "riskcode": "2", "confidence": "2", "desc": "<p>CORS</p>", "solution": "<p>Restrict it</p>", "instances": [{"uri": "https://mysite.com/", "method": "GET"}]},
                                     {"pluginid": "40012", "alert": "Cross Site Scripting (Reflected)", "riskcode": "3", "confidence": "2", "desc": "<p>XSS</p>"}]}]}
    with open(os.path.join(host_dir, "zap-report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f)
    sys.exit(0)

sys.exit(1)

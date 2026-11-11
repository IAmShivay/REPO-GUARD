import json
import os
import re
import subprocess
import tempfile
import urllib.request
from datetime import datetime, timedelta, timezone

OWNER = "IAmShivay"
REPOS = [
    "AGENCY_FORMIQ", "SHIVAY_PORTFOLIO", "PACKET-ANALYZER", "NAINA", "JOURNEYLOGS",
    "IAmShivay", "html-anime", "HARVEY", "doc-assistant", "CRM-BACKEND-SERVICES",
    "COMPUTER-SCIENCE", "ANNVAYA", "MOTORCAR_BACKEND", "MOTORCAR", "NGO_AB",
]
REQUIRED_RULESETS = {"lock-all-branches", "main-only-via-pr", "lock-all-tags"}
TRUSTED_BOTS = {"dependabot[bot]", "github-actions[bot]"}
LOOKBACK = timedelta(minutes=int(os.environ.get("LOOKBACK_MINUTES", "75")))
MALWARE = [
    (re.compile(rb"var\s+NX\s*,\s*SX\s*,\s*spin|var z = '-\d+|GSkqNNyuJw|95\.135\.181\.151"), "known PolinRider signature"),
    (re.compile(rb"\S[ \t]{150,}\S"), "code hidden after long blank space"),
    (re.compile(rb"node\s+(\./)?init(\.js)?\s*&&"), "'node init &&' loader in package.json"),
    (re.compile(rb"folderOpen|allowAutomaticTasks"), "VS Code autorun"),
]
SCAN_EXT = (".js", ".mjs", ".cjs", ".ts", ".json", ".ttf", ".woff", ".woff2", ".otf")
TOKEN = os.environ["GH_TOKEN"]


def api(path):
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, None


def scan_repo(name):
    found = []
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(
            ["git", "clone", "-q", "--depth", "1", f"https://github.com/{OWNER}/{name}.git", d],
            check=True, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        for dp, dns, fns in os.walk(d):
            dns[:] = [x for x in dns if x not in (".git", "node_modules")]
            for fn in fns:
                if fn in ("init", "init.js"):
                    found.append(f"loader file `{os.path.relpath(os.path.join(dp, fn), d)}`")
                    continue
                if not fn.endswith(SCAN_EXT) and fn not in ("tasks.json", "settings.json") or fn.endswith(".min.js") or "lock" in fn:
                    continue
                p = os.path.join(dp, fn)
                data = open(p, "rb").read()
                if fn.endswith((".ttf", ".woff", ".woff2", ".otf")):
                    if data[:4] not in (b"\x00\x01\x00\x00", b"true", b"OTTO", b"wOFF", b"wOF2", b"ttcf"):
                        found.append(f"fake font `{os.path.relpath(p, d)}`")
                    continue
                for rx, label in MALWARE:
                    if rx.search(data):
                        found.append(f"{label} in `{os.path.relpath(p, d)}`")
                        break
    return found


now = datetime.now(timezone.utc)
since = now - LOOKBACK
alerts = []

for name in REPOS:
    status, repo = api(f"/repos/{OWNER}/{name}")
    if status != 200:
        alerts.append(f"**{name}**: repository is missing or inaccessible (HTTP {status})")
        continue
    if repo.get("visibility") != "public":
        alerts.append(f"**{name}**: visibility changed to `{repo.get('visibility')}`")

    _, rulesets = api(f"/repos/{OWNER}/{name}/rulesets")
    active = set()
    for rs in rulesets or []:
        _, full = api(f"/repos/{OWNER}/{name}/rulesets/{rs['id']}")
        if full and full.get("enforcement") == "active" and not full.get("bypass_actors"):
            active.add(full["name"])
    missing = REQUIRED_RULESETS - active
    if missing:
        alerts.append(f"**{name}**: lock rules turned off, missing, or given a bypass: {', '.join(sorted(missing))}")

    _, events = api(f"/repos/{OWNER}/{name}/activity?per_page=30")
    pushed = False
    for e in events or []:
        ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
        if ts < since:
            continue
        actor = (e.get("actor") or {}).get("login", "unknown")
        kind = e.get("activity_type")
        ref = e.get("ref", "").replace("refs/heads/", "")
        if kind in ("force_push", "branch_deletion"):
            alerts.append(f"**{name}**: `{kind}` on `{ref}` by `{actor}` at {e['timestamp']}")
        elif actor not in TRUSTED_BOTS and actor != OWNER:
            alerts.append(f"**{name}**: `{kind}` on `{ref}` by unexpected account `{actor}` at {e['timestamp']}")
        if kind in ("push", "force_push", "pr_merge", "merge_queue_merge"):
            pushed = True

    if pushed:
        try:
            for f in scan_repo(name):
                alerts.append(f"**{name}**: MALWARE PATTERN on default branch: {f}")
        except subprocess.CalledProcessError as e:
            alerts.append(f"**{name}**: could not clone for malware scan ({e})")

print(f"checked {len(REPOS)} repos since {since:%Y-%m-%d %H:%M} UTC, {len(alerts)} alert(s)")
for a in alerts:
    print(" -", a)

if alerts:
    body = "Repo Guard found something that needs your attention:\n\n" + "\n".join(f"- {a}" for a in alerts)
    body += "\n\nIf you did not do this yourself, assume a token is stolen: revoke all sessions/apps on GitHub and check your PC."
    with open(os.environ.get("GITHUB_STEP_SUMMARY", os.devnull), "a") as s:
        s.write(body)
    subprocess.run(
        ["gh", "issue", "create", "--repo", os.environ["GITHUB_REPOSITORY"],
         "--title", f"ALERT: {len(alerts)} security event(s) {now:%Y-%m-%d %H:%M} UTC", "--body", body],
        check=True,
    )

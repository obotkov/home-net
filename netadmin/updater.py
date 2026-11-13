"""Проверка и установка обновлений с GitHub.

Версия берётся из VERSION.json, который пишет install.sh. Обновление запускает install.sh
отдельным systemd-юнитом (systemd-run): install.sh перезапускает сервис netadmin, и процесс
внутри сервиса был бы убит вместе с ним.
"""
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / "VERSION.json"
LOG = Path(os.environ.get("NETADMIN_STATE", "/var/lib/netadmin/state.json")).resolve().parent / "update.log"
UNIT = "netadmin-update"


def current():
    try:
        v = json.loads(VERSION_FILE.read_text())
    except (OSError, ValueError):
        v = {}
    return {
        "repo": v.get("repo") or os.environ.get("NETADMIN_REPO", "obotkov/home-net"),
        "ref": v.get("ref") or os.environ.get("NETADMIN_REF", "main"),
        "sha": v.get("sha") if v.get("sha") not in (None, "unknown") else None,
        "installed_at": v.get("installed_at"),
    }


def _gh(path):
    req = urllib.request.Request(f"https://api.github.com{path}", headers={
        "Accept": "application/vnd.github+json", "User-Agent": "netadmin-updater"})
    tok = os.environ.get("NETADMIN_GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def _commit_view(c):
    msg = c["commit"]["message"].splitlines()[0]
    return {"sha": c["sha"], "short": c["sha"][:7], "title": msg, "date": c["commit"]["committer"]["date"],
            "url": c.get("html_url")}


def check():
    cur = current()
    try:
        latest = _gh(f"/repos/{cur['repo']}/commits/{cur['ref']}")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"GitHub ответил {e.code}" + (" (лимит запросов, попробуйте позже)" if e.code == 403 else ""))
    except OSError as e:
        raise RuntimeError(f"нет связи с GitHub: {e}")
    res = {"current": cur, "latest": _commit_view(latest), "checked_at": int(time.time())}
    if cur["sha"] == latest["sha"]:
        res.update(update_available=False, behind=0, changes=[])
        return res
    changes, behind = [], None
    if cur["sha"]:
        try:
            cmp = _gh(f"/repos/{cur['repo']}/compare/{cur['sha']}...{latest['sha']}")
            behind = cmp.get("ahead_by")
            changes = [_commit_view(c) for c in reversed(cmp.get("commits", []))][:30]
        except (urllib.error.HTTPError, OSError):
            pass
    res.update(update_available=True, behind=behind, changes=changes or [_commit_view(latest)])
    return res


def status():
    log = ""
    try:
        log = LOG.read_text()[-15000:]
    except OSError:
        pass
    state = "idle"
    if log.startswith("[демо]"):
        state = "demo"
    elif shutil.which("systemctl"):
        st = subprocess.run(["systemctl", "show", "-p", "ActiveState", "-p", "Result", "--value", UNIT],
                            capture_output=True, text=True).stdout.split()
        if st and st[0] in ("active", "activating"):
            state = "running"
        elif log:
            state = "ok" if "netadmin работает" in log or "код обновлён" in log else "error"
    return {"state": state, "log": log, "version": current()}


def start(demo=False):
    if demo:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        LOG.write_text("[демо] обновление не выполняется в демо-режиме\n")
        return {"state": "ok"}
    if os.geteuid() != 0:
        raise RuntimeError("обновление из панели требует запуска сервиса от root")
    if not shutil.which("systemd-run"):
        raise RuntimeError("нет systemd-run; обновите вручную командой установки")
    if status()["state"] == "running":
        raise RuntimeError("обновление уже идёт")
    cur = current()
    url = f"https://raw.githubusercontent.com/{cur['repo']}/{cur['ref']}/install.sh"
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text(f"== {time.strftime('%Y-%m-%d %H:%M:%S')} обновление с {cur['repo']}@{cur['ref']}\n")
    script = (f"set -o pipefail; curl -fsSL '{url}' -o /tmp/netadmin-install.sh "
              f"&& NETADMIN_NONINTERACTIVE=1 NETADMIN_REPO='{cur['repo']}' NETADMIN_REF='{cur['ref']}' "
              f"bash /tmp/netadmin-install.sh 2>&1 | sed -u 's/\\x1b\\[[0-9;]*m//g' >> '{LOG}'")
    subprocess.run(["systemctl", "reset-failed", UNIT], capture_output=True)
    r = subprocess.run(["systemd-run", "--unit", UNIT, "--collect", "--quiet",
                        "-p", "TimeoutStartSec=900", "/bin/bash", "-c", script],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("не удалось запустить обновление: " + (r.stderr or r.stdout).strip())
    return {"state": "running"}

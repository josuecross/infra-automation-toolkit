#!/usr/intel/bin/python3
import UsrIntel.R1
try:
    import UsrIntel.R2
except Exception:
    pass

import argparse
import csv
import json
import os
import random
import re
import shlex
import subprocess
from typing import Optional, Tuple

# ---------- helpers ----------

def run(cmd: str, timeout: int = 60) -> Tuple[int, str]:
    p = subprocess.run(
        cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=timeout
    )
    return p.returncode, p.stdout

def parse_check_hosts(out: str) -> Optional[str]:
    """
    Expects:
      Host,Status
      <host>,ONLINE|OFFLINE
    """
    lines = out.strip().splitlines()
    if len(lines) < 2:
        return None
    reader = csv.DictReader(lines)
    for row in reader:
        status = (row.get("Status") or "").strip().upper()
        if status in ("ONLINE", "OFFLINE"):
            return status
    return None

JOB_RE = re.compile(r"JobID\s+(\d+),\s*Class\s+(\S+),\s*Queue\s+(\S+),\s*Slot\s+(.+)\)$")

def parse_nbjob_run(out: str):
    data = {
        "jobId": None,
        "class": None,
        "queue": None,
        "slot": None,
        "raw": out.strip()
    }
    for line in out.splitlines():
        m = JOB_RE.search(line)
        if m:
            data["jobId"] = m.group(1)
            data["class"] = m.group(2)
            data["queue"] = m.group(3)
            data["slot"]  = m.group(4)
            break
    return data

def build_invoke_command(action: str, server: str, site: str, ticket: str) -> str:
    """
    Build the exact python command for the chosen action.
    All scripts receive --site (where applicable), the server, and --ticket <ticket>.
    Called via bash -lc to load env.
    """
    # Adjust paths here if your files live elsewhere
    base = "~/work/run_step"

    mapping = {
        # Legacy flow with SUM (explicitly confirmed)
        "pxe_restart_legacy": f"python3 {base}/invoke_pxe_restart_legacy.py --site {shlex.quote(site)} --ticket {shlex.quote(ticket)} {shlex.quote(server)}",

        # Other invoke scripts present in your dir list
        "bmc_restart":        f"python3 {base}/invoke_bmc_restart.py --site {shlex.quote(site)} --ticket {shlex.quote(ticket)} {shlex.quote(server)}",
        "power_on":           f"python3 {base}/invoke_power_on.py --site {shlex.quote(site)} --ticket {shlex.quote(ticket)} {shlex.quote(server)}",
        "ac_cycle":           f"python3 {base}/invoke_ac_cycle_blades.py --site {shlex.quote(site)} --ticket {shlex.quote(ticket)} {shlex.quote(server)}",
        "fix_cobbler":        f"python3 {base}/invoke_fix_cobbler.py --ticket {shlex.quote(ticket)} {shlex.quote(server)}",

        # New ones from your listing:
        "pxe_rebuild":        f"python3 {base}/invoke_pxe_rebuild.py --site {shlex.quote(site)} --ticket {shlex.quote(ticket)} {shlex.quote(server)}",
        "bios_menu":          f"python3 {base}/invoke_bios_menu.py --site {shlex.quote(site)} --ticket {shlex.quote(ticket)} {shlex.quote(server)}",
    }
    if action not in mapping:
        raise SystemExit(f"Unknown action: {action}")
    return mapping[action]

# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(
        description="Check server; if OFFLINE, submit invoke action via Netbatch (passes --ticket) and output JSON."
    )
    ap.add_argument("--site", default="sc")
    ap.add_argument("--server", required=True)
    ap.add_argument("--ticket", required=True, help="ServiceNow ticket to update from the invoke script")
    ap.add_argument("--action", required=True,
                    choices=[
                        "pxe_restart_legacy",
                        "bmc_restart",
                        "power_on",
                        "ac_cycle",
                        "fix_cobbler",
                        "pxe_rebuild",
                        "bios_menu",
                    ])
    ap.add_argument("--qslot", required=True, help='e.g. "/EC/WORK"')
    ap.add_argument("--target", required=True, help="e.g. sc_interactive")
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args()

    short = args.server.split(".", 1)[0]

    # 1) health check (use your run_step path)
    rc, chk_out = run(f"python3 ~/work/run_step/check_hosts.py {shlex.quote(short)}", timeout=args.timeout)
    status = parse_check_hosts(chk_out) if rc == 0 else None

    # unique per-host log file under /tmp
    rand = random.randint(100000, 999999)
    log_file = f"/tmp/{short}_{rand}.log"

    result = {
        "server": short,
        "site": args.site,
        "ticket": args.ticket,
        "action": args.action,
        "server_status": status or "UNKNOWN",
        "action_submitted": False,
        "nbjob": None,
        "log_file": log_file,
        "errors": [],
        "check_raw": chk_out.strip(),
    }

    if status is None:
        result["errors"].append("Could not parse server status from check_hosts output.")
        print(json.dumps(result, indent=2))
        return

    if status == "ONLINE":
        # Don't submit—respect the requirement.
        print(json.dumps(result, indent=2))
        return

    # 2) build invoke and submit via Netbatch (bash -lc to load env)
    invoke_cmd = build_invoke_command(args.action, short, args.site, args.ticket)
    wrapped = f"bash -lc {shlex.quote(invoke_cmd)}"
    nb_cmd = (
        f'nbjob run --qslot {shlex.quote(args.qslot)} '
        f'--log-file {shlex.quote(log_file)} '
        f'--target {shlex.quote(args.target)} '
        f'{wrapped}'
    )

    rc2, nb_out = run(nb_cmd, timeout=args.timeout)
    job_info = parse_nbjob_run(nb_out)
    result["action_submitted"] = (job_info.get("jobId") is not None) and (rc2 == 0)
    result["nbjob"] = job_info
    if rc2 != 0:
        result["errors"].append(f"nbjob run exited with rc={rc2}")

    print("++json++" + json.dumps(result, indent=2) + "++json++" )

if __name__ == "__main__":
    main()

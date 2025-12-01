#!/usr/intel/bin/python3
import UsrIntel.R1  # must be first per Intel BKM
try:
    import UsrIntel.R2  # prefer newer release if present
except Exception:
    pass

# invoke_ac_cycle_blades.py
import argparse
import re
import shlex
import subprocess
from typing import Dict, Tuple

from site_creds import get_site_credentials
from sn_update import update_ticket

UMATCH_RE = re.compile(r"^\s*(\S+)\s+(\d+)\s*$")


def _run(cmd: str, timeout: int = 30) -> Tuple[int, str]:
    p = subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    return p.returncode, p.stdout


def _short(hostname: str) -> str:
    return hostname.split(".", 1)[0]


def Invoke_AcCycleBlades_one(
    server: str,
    site: str = "sc",
    redfish_py: str = "~/work/redfish_mgmt_utility/redfish_mgmt.py",
    timeout: int = 30,
) -> Dict[str, str]:
    print("== Action: AcCycleBlades ==")
    results: Dict[str, str] = {}

    # Load credentials from keyring (ordered)
    credentials = get_site_credentials(site)
    if not credentials:
        results[_short(server)] = "[Fail] No stored credentials for site"
        return results

    short = _short(server)
    print(f"[ACCYCLE] Processing {short}")

    # --- Capture umatch command & output ---
    umatchCmd = f"umatch nodes {shlex.quote(short)} enclosure bay"
    rc, umatch_out = _run(umatchCmd, timeout=15)
    if rc != 0:
        results[short] = f"[Fail] umatch enclosure bay failed: {umatch_out.strip()}"
        print(f"[ACCYCLE] Done {short}")
        return results

    cmm = blade = None
    for line in umatch_out.splitlines():
        m = UMATCH_RE.match(line)
        if m:
            cmm, blade = m.group(1), m.group(2)
            break
    if not cmm or not blade:
        results[short] = f"[Fail] umatch enclosure bay failed: {umatch_out.strip() or 'no output'}"
        print(f"[ACCYCLE] Done {short}")
        return results

    final = ""
    success = False
    lastCmd = ""
    lastOut = ""

    for user, pw in credentials:
        cmd = (
            f"{redfish_py} --accycle_blade {shlex.quote(blade)} "
            f"-u {shlex.quote(user)} -p {shlex.quote(pw)} "
            f"-m {shlex.quote(cmm + '.' + site + '.intel.com')}"
        )
        print(f"[ACCYCLE] Run → {cmd}")
        rc2, out = _run(cmd, timeout=timeout)
        txt = out
        final = txt
        lastCmd = cmd
        lastOut = txt
        if "Unable to create Redfish session" not in txt and rc2 == 0:
            success = True
            break

    if not success:
        final = (
            "[Fail] Redfish ac-cycle failed for all credentials"
            if not final.strip()
            else f"[Fail] {final.strip()}"
        )
        results[short] = final
        print(f"[ACCYCLE] Done {short}")
        return results

    # redact password in command for logging
    redacted = lastCmd
    for _, pw in credentials:
        if pw and pw in redacted:
            redacted = redacted.replace(pw, "*pass*")

    # --- On success, append the commands & outputs (PowerShell-like here-string) ---
    block = f"""

{umatchCmd}


{umatch_out.strip()}


{redacted}


{lastOut.strip()}
"""
    results[short] = block
    print(f"[ACCYCLE] Done {short}")
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="AC-cycle a single blade and update a ServiceNow ticket."
    )
    ap.add_argument("--site", default="sc")
    ap.add_argument("--redfish", default="~/work/redfish_mgmt_utility/redfish_mgmt.py")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--ticket", required=True, help="ServiceNow ticket number to update")
    ap.add_argument("server", help="Single server name (FQDN or short)")
    args = ap.parse_args()

    r = Invoke_AcCycleBlades_one(
        args.server, site=args.site, redfish_py=args.redfish, timeout=args.timeout
    )

    # console view
    for k, v in r.items():
        print(f"\n--- {k} ---\n{v}")

    # push to ServiceNow
    ok, logs = update_ticket(args.ticket, r)
    print("\n=== ServiceNow update ===")
    print("Status:", "OK" if ok else "FAIL")
    for i, log in enumerate(logs, 1):
        print(f"[chunk {i}] {log}")

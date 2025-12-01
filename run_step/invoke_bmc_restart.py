#!/usr/intel/bin/python3
import UsrIntel.R1  # must be first per Intel BKM
try:
    import UsrIntel.R2  # prefer newer release if present
except Exception:
    pass

# invoke_bmc_restart.py
import argparse
import shlex
import subprocess
from typing import Dict, Tuple

from site_creds import get_site_credentials
from sn_update import update_ticket


def _run(cmd: str, timeout: int = 30) -> Tuple[int, str]:
    """Run a shell command and capture its output."""
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
    """Return short name (before first dot)."""
    return hostname.split(".", 1)[0]


def Invoke_BMCrestart_one(
    server: str,
    site: str = "sc",
    redfish_py: str = "~/work/redfish_mgmt_utility/redfish_mgmt.py",
    timeout: int = 30,
) -> Dict[str, str]:
    """
    Run BMC reset for a single server. Returns { short: <here-string-like block> }.
    """
    print("== Action: BMCrestart ==")
    results: Dict[str, str] = {}

    # Load credentials from keyring (ordered per site_creds.DEFAULT_USERS)
    credentials = get_site_credentials(site)
    if not credentials:
        msg = "[Fail] No stored credentials for site"
        results[_short(server)] = msg
        return results

    short = _short(server)
    print(f"[BMCrestart] Processing {short}")

    final = ""
    success = False
    last_cmd = ""
    last_out = ""

    for user, pw in credentials:
        cmd = (
            f"{redfish_py} -n {shlex.quote(short)} "
            f"--reset_bmc -u {shlex.quote(user)} -p {shlex.quote(pw)}"
        )
        print(f"[BMCrestart] Run → {cmd}")
        rc, out = _run(cmd, timeout=timeout)
        txt = out
        final = txt
        last_cmd = cmd
        last_out = txt
        if "Unable to create Redfish session" not in txt and rc == 0:
            success = True
            break

    if not success:
        final = (
            "[Fail] Redfish BMC reset failed for all credentials"
            if not final.strip()
            else f"[Fail] {final.strip()}"
        )
        results[short] = final
        print(f"[BMCrestart] Done {short}")
        return results

    # Redact password anywhere it may appear in the recorded command
    redacted = last_cmd
    for _, pw in credentials:  # mask any of the tried passwords
        if pw and pw in redacted:
            redacted = redacted.replace(pw, "*pass*")

    # Success: include raw command + output (PowerShell-like block)
    block = f"""

{redacted}
{last_out.strip()}
"""
    results[short] = block
    print(f"[BMCrestart] Done {short}")

    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Reset BMC for a single server and update a ServiceNow ticket."
    )
    ap.add_argument("--site", default="sc", help="Site code used for keyring service (default: sc)")
    ap.add_argument("--redfish", default="~/work/redfish_mgmt_utility/redfish_mgmt.py",
                    help="Path to redfish_mgmt.py")
    ap.add_argument("--timeout", type=int, default=30, help="Per-command timeout seconds")
    ap.add_argument("--ticket", required=True, help="ServiceNow ticket number to update")
    ap.add_argument("server", help="Single server name (FQDN or short)")
    args = ap.parse_args()

    # Run BMC reset for one server
    results = Invoke_BMCrestart_one(
        args.server,
        site=args.site,
        redfish_py=args.redfish,
        timeout=args.timeout,
    )

    # Print local console view
    for k, v in results.items():
        print(f"\n--- {k} ---\n{v}")

    # Update ServiceNow work notes
    ok, logs = update_ticket(args.ticket, results)
    print("\n=== ServiceNow update ===")
    print("Status:", "OK" if ok else "FAIL")
    for i, log in enumerate(logs, 1):
        print(f"[chunk {i}] {log}")

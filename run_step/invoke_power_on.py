#!/usr/intel/bin/python3
import UsrIntel.R1  # must be first per Intel BKM
try:
    import UsrIntel.R2  # prefer newer release if present
except Exception:
    pass

# invoke_power_on.py
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


def Invoke_PowerOn_one(
    server: str,
    site: str = "sc",
    redfish_py: str = "~/work/redfish_mgmt_utility/redfish_mgmt.py",
    timeout: int = 30,
) -> Dict[str, str]:
    """
    Power on a single server via redfish_mgmt.py using site creds from keyring.
    Returns { short: <here-string-like block> }.
    """
    print("== Action: PowerOn ==")
    results: Dict[str, str] = {}

    # Load credentials from keyring (ordered per site_creds)
    credentials = get_site_credentials(site)
    if not credentials:
        results[_short(server)] = "[Fail] No stored credentials for site"
        return results

    short = _short(server)
    print(f"[POWERON] Processing {short}")

    final = ""
    success = False
    last_cmd = ""
    last_out = ""

    for user, pw in credentials:
        cmd = " ".join(
            [
                redfish_py,
                "-n",
                shlex.quote(short),
                "--power_on",
                "-u",
                shlex.quote(user),
                "-p",
                shlex.quote(pw),
            ]
        )
        print(f"[POWERON] Run → {cmd}")
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
            "[Fail] Redfish power_on failed for all credentials"
            if not final.strip()
            else f"[Fail] {final.strip()}"
        )
        results[short] = final
        print(f"[POWERON] Done {short}")
        return results

    # Redact password anywhere it may appear in the recorded command
    redacted = last_cmd
    for _, pw in credentials:
        if pw and pw in redacted:
            redacted = redacted.replace(pw, "*pass*")

    # Success block (matches your PowerShell style)
    block = f"""

{redacted}
{last_out.strip()}
"""
    results[short] = block
    print(f"[POWERON] Done {short}")

    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Power on a single server and update a ServiceNow ticket."
    )
    ap.add_argument("--site", default="sc", help="Site code used for keyring service (default: sc)")
    ap.add_argument("--redfish", default="~/work/redfish_mgmt_utility/redfish_mgmt.py",
                    help="Path to redfish_mgmt.py (default: ~/work/redfish_mgmt_utility/redfish_mgmt.py)")
    ap.add_argument("--timeout", type=int, default=30, help="Per-command timeout seconds")
    ap.add_argument("--ticket", required=True, help="ServiceNow ticket number to update")
    ap.add_argument("server", help="Single server name (FQDN or short)")
    args = ap.parse_args()

    # Run action
    r = Invoke_PowerOn_one(
        args.server,
        site=args.site,
        redfish_py=args.redfish,
        timeout=args.timeout,
    )

    # Console output
    for k, v in r.items():
        print(f"\n--- {k} ---\n{v}")

    # Update ServiceNow ticket
    ok, logs = update_ticket(args.ticket, r)
    print("\n=== ServiceNow update ===")
    print("Status:", "OK" if ok else "FAIL")
    for i, log in enumerate(logs, 1):
        print(f"[chunk {i}] {log}")

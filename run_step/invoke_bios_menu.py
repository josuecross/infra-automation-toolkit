#!/usr/intel/bin/python3
import UsrIntel.R1  # must be first per Intel BKM
try:
    import UsrIntel.R2  # prefer newer release if present
except Exception:
    pass

# invoke_pxe_restart.py
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
    """Return the short hostname (before the first dot)."""
    return hostname.split(".", 1)[0]


def Invoke_PxeRestart_one(
    server: str,
    site: str = "sc",
    redfish_py: str = "~/work/redfish_mgmt_utility/redfish_mgmt.py",
    timeout: int = 30,
) -> Dict[str, str]:
    """
    PXE Restart logic for a single host:
      - Iterate site credentials (from keyring)
      - Run set_onetime_boot first
      - If success, run restart
      - Stop on first success
      - Return { short: here-string-like block }
    """
    print("== Action: PxeRestart ==")
    results: Dict[str, str] = {}

    credentials = get_site_credentials(site)
    short = _short(server)

    if not credentials:
        results[short] = "[Fail] No stored credentials for site"
        return results

    print(f"[PXErestart] Processing {short}")

    final = ""
    success = False
    boot_cmd = ""
    boot_out = ""
    restart_cmd = ""
    restart_out = ""

    for user, pw in credentials:
        # 1) set_onetime_boot first
        boot_cmd = (
            f"{redfish_py} -n {shlex.quote(short)} "
            f"--set_onetime_boot 'Pxe' 'Legacy' "
            f"-u {shlex.quote(user)} -p {shlex.quote(pw)}"
        )
        print(f"[PXErestart] Set boot → {boot_cmd}")
        rc_b, boot_out = _run(boot_cmd, timeout=timeout)
        if "Unable to create Redfish session" in boot_out or rc_b != 0:
            final = boot_out
            continue  # try next credential

        # 2) restart
        restart_cmd = (
            f"{redfish_py} -n {shlex.quote(short)} "
            f"--restart -u {shlex.quote(user)} -p {shlex.quote(pw)}"
        )
        print(f"[PXErestart] Restart → {restart_cmd}")
        rc_r, restart_out = _run(restart_cmd, timeout=timeout)
        final = restart_out

        if "Unable to create Redfish session" not in restart_out and rc_r == 0:
            success = True
            break

    # 3) record results
    if success:
        # redact any tried password in the visible commands
        redacted_boot = boot_cmd
        redacted_restart = restart_cmd
        for _, pw in credentials:
            if pw:
                redacted_boot = redacted_boot.replace(pw, "*pass*")
                redacted_restart = redacted_restart.replace(pw, "*pass*")

        block = f"""

{redacted_boot}
{boot_out.strip()}

{redacted_restart}
{restart_out.strip()}
"""
        results[short] = block
    else:
        results[short] = f"[Fail] {final.strip() or 'Redfish PXE restart failed for all credentials'}"

    print(f"[PXErestart] Done {short}")
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="PXE Legacy restart (set_onetime_boot → restart) for a single server; updates a ServiceNow ticket."
    )
    ap.add_argument("--site", default="sc")
    ap.add_argument("--redfish", default="~/work/redfish_mgmt_utility/redfish_mgmt.py")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--ticket", required=True, help="ServiceNow ticket number to update")
    ap.add_argument("server", help="Single server name (FQDN or short)")
    args = ap.parse_args()

    # Run action
    r = Invoke_PxeRestart_one(
        args.server,
        site=args.site,
        redfish_py=args.redfish,
        timeout=args.timeout,
    )

    # Console output
    for k, v in r.items():
        print(f"\n--- {k} ---\n{v}")

    # Update ServiceNow work notes
    ok, logs = update_ticket(args.ticket, r)
    print("\n=== ServiceNow update ===")
    print("Status:", "OK" if ok else "FAIL")
    for i, log in enumerate(logs, 1):
        print(f"[chunk {i}] {log}")

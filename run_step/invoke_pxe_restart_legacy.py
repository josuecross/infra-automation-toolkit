#!/usr/intel/bin/python3
import UsrIntel.R1  # Intel BKM: must be first
try:
    import UsrIntel.R2
except Exception:
    pass

# invoke_pxe_restart_legacy.py
import argparse
import os
import re
import shlex
import subprocess
from typing import Dict, List, Tuple

from site_creds import get_site_credentials
from sn_update import update_ticket

# ---------- Helpers ----------
RE_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

def _run(cmd: str, timeout: int = 60) -> Tuple[int, str]:
    p = subprocess.run(
        cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=timeout
    )
    return p.returncode, p.stdout

def _short(hostname: str) -> str:
    return hostname.split(".", 1)[0]

def _log_new() -> List[str]:
    return []

def _log_add(log: List[str], line: str) -> None:
    log.append(line)

def _mask_creds(s: str, user: str, pw: str) -> str:
    out = s
    if user:
        out = out.replace(user, "*User*")
    if pw:
        out = out.replace(pw, "*Pass*")
    return out

def _home(path: str) -> str:
    return os.path.expanduser(path)

# ---------- Core ----------
def Invoke_PXErestartLegacy_one(
    server: str,
    site: str = "sc",
    rfPath: str = "~/work/redfish_mgmt_utility/redfish_mgmt.py",
    sumBin: str = "~/work/sum-2.7",
    timeout: int = 60,
) -> Dict[str, str]:
    """
    Force Legacy Boot for a single server (Redfish → SUM → Redfish reboot), running locally.
      1) umatch nodes <short> mgmt → parse mgmt IP
      2) Redfish: --set_onetime_boot 'Pxe' 'Legacy' (iterate site creds until success)
      3) SUM: GetCurrentBiosCfg → bios_sed.sh auto → ChangeBiosCfg --skip_unknown --skip_bbs
      4) Redfish: --restart
    Returns: { short: multi-line log block }
    """
    print("== Force Legacy Boot (Redfish → SUM → Redfish reboot) ==")
    rfPath = _home(rfPath)
    sumBin = _home(sumBin)
    bios_sed = _home("~/work/bios_sed.sh")

    # site credentials from keyring
    credentials = get_site_credentials(site)
    short = _short(server)
    results: Dict[str, str] = {}

    if not credentials:
        results[short] = "[Fail] No stored credentials for site"
        return results

    log = _log_new()
    _log_add(log, f"----- [{short}] START -----")
    print(f"\n----- [{short}] START -----")

    # STEP 1: mgmt IP
    _log_add(log, f"[{short}][STEP 1] Getting mgmt IP...")
    mgmt_cmd = f"umatch nodes {shlex.quote(short)} mgmt"
    rc, mgmt_out = _run(mgmt_cmd, timeout=15)
    _log_add(log, f"umatch: {mgmt_out.strip()}")
    if rc != 0:
        _log_add(log, "[ERROR] mgmt IP command failed.")
        results[short] = "\n".join(log)
        print(f"----- [{short}] END (NO MGMT) -----")
        return results

    m = RE_IP.search(mgmt_out or "")
    mgmt = m.group(0) if m else None
    if not mgmt:
        _log_add(log, "[ERROR] mgmt IP not found.")
        results[short] = "\n".join(log)
        print(f"----- [{short}] END (NO MGMT) -----")
        return results
    _log_add(log, f"mgmt={mgmt}")

    # STEP 2: Redfish set Legacy PXE (always PXE)
    _log_add(log, f"[{short}][STEP 2] Set one-time PXE Legacy via Redfish...")
    user_used = None
    pass_used = None
    rf_ok = False

    for user, pw in credentials:
        rf_set_cmd = (
            f"{rfPath} --set_onetime_boot 'Pxe' 'Legacy' "
            f"-u {shlex.quote(user)} -p {shlex.quote(pw)} -n {shlex.quote(short)}"
        )
        rf_set_masked = _mask_creds(rf_set_cmd, user, pw)
        _log_add(log, f"Redfish cmd: {rf_set_masked}")
        rc_set, out_set = _run(rf_set_cmd, timeout=timeout)
        _log_add(log, f"Redfish OUT:\n{out_set.strip()}")
        if "Unable to create Redfish session" not in out_set and rc_set == 0:
            user_used, pass_used = user, pw
            rf_ok = True
            break

    if not rf_ok:
        _log_add(log, "[ERROR] Redfish (set_onetime_boot) failed for all users.")
        results[short] = "\n".join(log)
        print(f"----- [{short}] END (REDFISH AUTH FAIL) -----")
        return results

    # STEP 3: SUM (Dump → Edit → Load), running locally
    _log_add(log, f"[{short}][STEP 3] SUM (Dump → Edit → Load) ...")
    bios_tmp = f"/tmp/bios_{short}.xml"

    # 3.1 Dump current BIOS
    dump_cmd = (
        f"SUMBIN={shlex.quote(sumBin)} ; "
        f"$SUMBIN -i {shlex.quote(mgmt)} -u {shlex.quote(user_used)} -p {shlex.quote(pass_used)} "
        f"-c GetCurrentBiosCfg --file {shlex.quote(bios_tmp)}"
    )
    dump_masked = _mask_creds(dump_cmd, user_used, pass_used)
    _log_add(log, f"SUM Dump: {dump_masked}")
    rc_dump, out_dump = _run(dump_cmd, timeout=timeout)
    _log_add(log, f"SUM Dump OUT:\n{out_dump.strip()}")

    sum_ok = True
    if "<<<<<ERROR>>>>>" in out_dump:
        _log_add(log, "[WARN] SUM dump failed; will still reboot via Redfish.")
        sum_ok = False

    if sum_ok:
        # 3.3 Edit BIOS via script
        edit_cmd = f"bash -lc {shlex.quote(f'{bios_sed} auto {bios_tmp}')}"
        _log_add(log, f"SUM Edit: {edit_cmd}")
        rc_edit, out_edit = _run(edit_cmd, timeout=timeout)
        _log_add(log, f"SUM Edit OUT:\n{out_edit.strip()}")
        if "__SED_RC=0" not in out_edit:
            _log_add(log, "[WARN] bios_sed.sh returned non-zero; proceeding but SUM may not apply changes.")

        # 3.5 Load updated config
        load_cmd = (
            f"SUMBIN={shlex.quote(sumBin)} ; "
            f"$SUMBIN -i {shlex.quote(mgmt)} -u {shlex.quote(user_used)} -p {shlex.quote(pass_used)} "
            f"-c ChangeBiosCfg --file {shlex.quote(bios_tmp)} --skip_unknown --skip_bbs"
        )
        load_masked = _mask_creds(load_cmd, user_used, pass_used)
        _log_add(log, f"SUM Load: {load_masked}")
        rc_load, out_load = _run(load_cmd, timeout=timeout)
        _log_add(log, f"SUM Load OUT:\n{out_load.strip()}")
        if "<<<<<ERROR>>>>>" in out_load:
            _log_add(log, "[WARN] SUM load failed; proceeding to reboot anyway.")
        else:
            _log_add(log, "SUM Legacy + (optional) CSM applied.")

    # STEP 4: Redfish reboot (always)
    rb_cmd = (
        f"{rfPath} --restart -u {shlex.quote(user_used)} -p {shlex.quote(pass_used)} "
        f"-n {shlex.quote(short)}"
    )
    rb_masked = _mask_creds(rb_cmd, user_used, pass_used)
    _log_add(log, f"[{short}][STEP 4] Reboot via Redfish...")
    _log_add(log, f"Reboot cmd: {rb_masked}")
    rc_rb, out_rb = _run(rb_cmd, timeout=timeout)
    _log_add(log, f"Reboot OUT:\n{out_rb.strip()}")

    results[short] = "\n".join(log)
    print(f"----- [{short}] END (OK) -----")
    return results

# ---------- CLI ----------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="PXE Legacy (Redfish → SUM → Reboot) for a single server; posts results to ServiceNow."
    )
    ap.add_argument("--site", default="sc")
    ap.add_argument("--redfish", default="~/work/redfish_mgmt_utility/redfish_mgmt.py")
    ap.add_argument("--sum", default="~/work/sum-2.7")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--ticket", required=True, help="ServiceNow ticket number to update")
    ap.add_argument("server", help="Single server name (FQDN or short)")
    args = ap.parse_args()

    # Run for one server
    results = Invoke_PXErestartLegacy_one(
        args.server,
        site=args.site,
        rfPath=args.redfish,
        sumBin=args.sum,
        timeout=args.timeout,
    )

    # Console output
    for k, v in results.items():
        print(f"\n--- {k} ---\n{v}")

    # Update ServiceNow ticket
    ok, logs = update_ticket(args.ticket, results)
    print("\n=== ServiceNow update ===")
    print("Status:", "OK" if ok else "FAIL")
    for i, log in enumerate(logs, 1):
        print(f"[chunk {i}] {log}")

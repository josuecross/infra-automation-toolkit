#!/usr/intel/bin/python3
import UsrIntel.R1  # Intel BKM: must be first
try:
    import UsrIntel.R2
except Exception:
    pass

# invoke_fix_cobbler.py
import argparse
import json
import os
import re
import shlex
import subprocess
from typing import Dict, Tuple, Optional, List

from sudo_prime import prime_sudo
from sn_update import update_ticket
from site_creds import get_site_credentials

# --- Config ---
REDFISH_TOOL_DEFAULT = "~/work/redfish_mgmt_utility/redfish_mgmt.py"
BLADE_SCAN_MAX = 40  # we only use Node 1, but we may scan blades to find the right slot by BMCIP

# --- Regex helpers ---
RE_DNS_MAC = re.compile(r"([a-z0-9\.-]+\.intel\.com)\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
RE_CMM     = re.compile(r"\b(cmm-[a-z0-9\-\.]+\.intel\.com)\b", re.I)
RE_IPV4    = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

# --- Shell helpers ---
def _run(cmd: str, timeout: int = 30) -> Tuple[int, str]:
    p = subprocess.run(
        cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=timeout
    )
    return p.returncode, p.stdout

def _short(hostname: str) -> str:
    return hostname.split(".", 1)[0]

# --- Text/JSON helpers ---
def _first_json_block(text: str) -> Optional[dict]:
    s = text.find("{"); e = text.rfind("}")
    if s == -1 or e == -1 or e < s:
        return None
    try:
        return json.loads(text[s:e+1])
    except Exception:
        return None

def _norm_mac(mac: str) -> str:
    return mac.strip().lower()

def _is_empty_mac(mac: Optional[str]) -> bool:
    if not mac:
        return True
    m = _norm_mac(mac)
    return m in ("", "00:00:00:00:00:00")

# --- UMATCH: pull dnsdomain, macaddr (legacy), cmm and bmcip ---
def _umatch_all(short: str, timeout: int = 20) -> Tuple[str, Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Returns (full_output, dnsdomain, legacy_mac, cmm_host, bmc_ip)
    """
    cmd = f"umatch nodes {shlex.quote(short)} dnsdomain macaddr cmm bmc bmcip ip"
    rc, out = _run(cmd, timeout=timeout)
    # dns + mac (legacy format)
    dns = None; mac = None
    m = RE_DNS_MAC.search(out)
    if m:
        dns = m.group(1).strip()
        mac = _norm_mac(m.group(2).strip())
    # CMM host
    cmm = None
    mc = RE_CMM.search(out)
    if mc:
        cmm = mc.group(1).strip().lower()
    # BMC IP (prefer a line with "bmc"/"bmcip")
    bmc_ip = None
    for line in out.splitlines():
        if re.search(r"\bbmc(ip)?\b", line, flags=re.I):
            mi = RE_IPV4.search(line)
            if mi:
                bmc_ip = mi.group(0)
                break
    if not bmc_ip:
        mi = RE_IPV4.search(out)
        if mi:
            bmc_ip = mi.group(0)
    return out, dns, mac, cmm, bmc_ip

# --- DHCP/DNS sanity checks ---
def _mac_occurrences_in_dhcpd(mac: str, timeout: int = 20) -> Tuple[int, str]:
    mac_re = re.escape(_norm_mac(mac))
    cmd = f"sudo grep -n -B1 -i '{mac_re}' /etc/dhcpd.conf || true"
    _, out = _run(cmd, timeout=timeout)
    count = len(re.findall(r"(?i)hardware\s+ethernet\s+" + mac_re, out))
    return count, out

def _dns_check(fqdn: str, timeout: int = 15) -> Tuple[bool, str]:
    logs = []
    cmd_a = f"nslookup {shlex.quote(fqdn)}"
    _, out_a = _run(cmd_a, timeout=timeout)
    logs.append(f"$ {cmd_a}\n{out_a.strip()}\n")
    m = re.search(r"Address:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out_a)
    if not m:
        return False, "\n".join(logs) + "[DNS] Could not parse A record address."
    ip = m.group(1)
    cmd_ptr = f"nslookup {shlex.quote(ip)}"
    _, out_ptr = _run(cmd_ptr, timeout=timeout)
    logs.append(f"$ {cmd_ptr}\n{out_ptr.strip()}\n")
    m2 = re.search(r"name\s*=\s*([^\s]+)\.", out_ptr) or re.search(r"name\s*=\s*([^\s]+)", out_ptr)
    if not m2:
        return False, "\n".join(logs) + "[DNS] Could not parse PTR name."
    ptr = m2.group(1).rstrip(".")
    ok = (ptr.lower() == fqdn.lower())
    logs.append("[DNS] A and PTR both resolve to the FQDN." if ok else f"[DNS] PTR mismatch: got '{ptr}', expected '{fqdn}'")
    return ok, "\n".join(logs)

# --- Redfish helpers (use Node 1 only, try creds from keyring like invoke_power_on) ---
def _redfish_show(redfish_tool: str, cmm_host: str, path: str, user: str, password: str, timeout: int = 30) -> Tuple[int, str, str]:
    tool = os.path.expanduser(redfish_tool)
    parts = [shlex.quote(tool), "-m", shlex.quote(cmm_host), "--show", shlex.quote(path)]
    if user: parts += ["-u", shlex.quote(user)]
    if password: parts += ["-p", shlex.quote(password)]
    cmd = " ".join(parts)
    # Mask pw in display
    pdisp = parts[:]
    if password:
        try:
            idx = pdisp.index("-p") + 1
            pdisp[idx] = "'********'"
        except Exception:
            pass
    disp = " ".join(pdisp)
    rc, out = _run(cmd, timeout=timeout)
    return rc, out, disp

def _try_status_with_creds(redfish_tool: str, cmm_host: str, blade: int, creds: List[Tuple[str, str]], timeout: int = 30) -> Tuple[Optional[dict], str]:
    """
    Query /redfish/v1/Chassis/1/Blade/<blade>/Node/1/Status with each (user,pw) until success.
    Returns (json_dict_or_None, logs).
    """
    logs = []
    path = f"/redfish/v1/Chassis/1/Blade/{int(blade)}/Node/1/Status"
    for user, pw in creds:
        rc, out, disp = _redfish_show(redfish_tool, cmm_host, path, user, pw, timeout=timeout)
        logs.append(f"[CMM] {disp}")
        logs.append(out.strip())
        if rc == 0:
            data = _first_json_block(out)
            if data:
                return data, "\n".join(logs)
    return None, "\n".join(logs)

def _find_blade_and_nat1_by_bmcip(redfish_tool: str, cmm_host: str, target_bmc_ip: str,
                                  creds: List[Tuple[str, str]], timeout: int = 30) -> Tuple[Optional[int], Optional[str], str]:
    """
    Scan Blade 1..BLADE_SCAN_MAX, Node 1 only.
    When a Status JSON has BMCIP == target_bmc_ip, read NIC1MAC.
    Return (blade_index, nat1_mac, logs). If NIC1MAC empty/missing, return None for mac.
    """
    logs = []
    if not cmm_host or not target_bmc_ip:
        return None, None, "[CMM] Missing CMM host or target BMC IP.\n"
    for blade in range(1, BLADE_SCAN_MAX + 1):
        data, s_log = _try_status_with_creds(redfish_tool, cmm_host, blade, creds, timeout=timeout)
        logs.append(s_log)
        if not data:
            continue
        bmc_ip = (data.get("BMCIP") or data.get("BmcIp") or data.get("bmcip") or "").strip()
        if bmc_ip == target_bmc_ip:
            nat1 = data.get("NIC1MAC") or data.get("Nic1Mac") or data.get("nic1mac")
            nat1 = _norm_mac(nat1) if nat1 else None
            if _is_empty_mac(nat1):
                nat1 = None
            return blade, nat1, "\n".join(logs)
    return None, None, "\n".join(logs)

# --- Main action ---
def Invoke_FixCobbler_one(
    server: str,
    site: str = "sc",
    redfish_tool: str = REDFISH_TOOL_DEFAULT,
    timeout: int = 30,
) -> Dict[str, str]:
    """
    One-command flow:
      - umatch nodes → dnsdomain + cmm + bmcip (+ legacy macaddr)
      - fqdn = short + dnsdomain
      - Prefer Redfish Node 1: find blade by BMCIP, get NIC1MAC (NAT1)
        * If NIC1MAC missing/empty → fallback to umatch macaddr
      - Update Cobbler (short or fqdn, optional rename)
      - DHCP single-occurrence check; DNS A/PTR check
      - Return { short: consolidated block }
    """
    print("== Action: FixCobbler ==")

    # Sudo prime
    status, prime_out = prime_sudo()
    short = _short(server)
    if status != "ok":
        return { short: f"[Fail] Sudo prime failed locally: {prime_out.strip()}" }

    results: Dict[str, str] = {}
    print(f"[COBBLER] Processing {short}")

    # UMATCH basics
    umatch_out, dns_domain, legacy_mac, cmm_host, bmc_ip = _umatch_all(short, timeout=20)
    if not dns_domain:
        results[short] = f"[Fail] umatch did not provide dnsdomain.\n{umatch_out}"
        return results
    fqdn = f"{short}.{dns_domain}"

    print(f"[UMATCH] fqdn={fqdn}  cmm={cmm_host}  bmc_ip={bmc_ip}  legacy_mac={legacy_mac}")

    # Redfish creds (same model as invoke_power_on)
    credentials = get_site_credentials(site) or []
    # If no creds configured, attempt a very basic default like invoke_power_on did
    if not credentials:
        credentials = [("remadm", "")]

    # Prefer NAT1 MAC via Redfish Node 1 (by matching BMCIP to locate blade)
    nat1_mac = None
    cmm_logs = ""
    blade_found = None
    if cmm_host and bmc_ip:
        blade_found, nat1_mac, cmm_logs = _find_blade_and_nat1_by_bmcip(
            redfish_tool=os.path.expanduser(redfish_tool),
            cmm_host=cmm_host,
            target_bmc_ip=bmc_ip,
            creds=credentials,
            timeout=timeout,
        )

    # Fallback to legacy mac via umatch if Redfish failed or NIC1MAC empty
    if not nat1_mac and legacy_mac:
        nat1_mac = legacy_mac

    if not nat1_mac:
        results[short] = (
            f"[Fail] Could not determine NAT1 (NIC1) MAC from Redfish Node 1, and no legacy MAC available.\n\n"
            f"[UMATCH output]\n{umatch_out}\n\n[CMM scan logs]\n{cmm_logs}\n"
        )
        return results

    print(f"[MAC] Using NAT1 MAC = {nat1_mac} (blade={blade_found or 'unknown'})")

    # Determine which Cobbler system exists
    report_short_cmd = f"cobbler system report --name {shlex.quote(short)}"
    _, report_short = _run(report_short_cmd, timeout=timeout)
    use_name = short
    if re.search(r"(?i)\bNo system found\b", report_short):
        report_fqdn_cmd = f"cobbler system report --name {shlex.quote(fqdn)}"
        _, report_fqdn = _run(report_fqdn_cmd, timeout=timeout)
        if re.search(r"(?i)\bNo system found\b", report_fqdn):
            results[short] = (
                "[Fail] No matching Cobbler system found with either "
                f"'{short}' or '{fqdn}'.\n\n[report(short)]\n{report_short.strip()}\n\n[report(fqdn)]\n{report_fqdn.strip()}\n"
            )
            return results
        use_name = fqdn
        report_cmd_used = report_fqdn_cmd
        report_out_used = report_fqdn
    else:
        report_cmd_used = report_short_cmd
        report_out_used = report_short

    print(f"[COBBLER] Using system name: {use_name}")

    # Apply edits (sudo)
    edit_meta = f"sudo cobbler system edit --name {shlex.quote(use_name)} --autoinstall-meta ''"
    edit_mac  = f"sudo cobbler system edit --name {shlex.quote(use_name)} --mac-address {shlex.quote(nat1_mac)}"
    print(f"[COBBLER] Run → {edit_meta}")
    _, r_meta = _run(edit_meta, timeout=timeout)
    print(f"[COBBLER] Run → {edit_mac}")
    _, r_mac = _run(edit_mac, timeout=timeout)

    # Optional rename short -> FQDN when not sc.intel.com and we matched short
    rename_cmd = ""
    r_rename   = ""
    report_cmd = ""
    report_out = ""
    if use_name == short and dns_domain != "sc.intel.com":
        rename_cmd = (
            f"sudo cobbler system rename --name={shlex.quote(short)} "
            f"--newname={shlex.quote(fqdn)} --hostname={shlex.quote(fqdn)}"
        )
        print(f"[COBBLER] Rename short → FQDN (domain={dns_domain}) → {rename_cmd}")
        _, r_rename = _run(rename_cmd, timeout=timeout)
        report_cmd = f"cobbler system report --name {shlex.quote(fqdn)}"
        _, report_out = _run(report_cmd, timeout=timeout)
    else:
        report_cmd = f"cobbler system report --name {shlex.quote(use_name)}"
        _, report_out = _run(report_cmd, timeout=timeout)

    # Sanity checks
    dhcp_count, dhcp_grep = _mac_occurrences_in_dhcpd(nat1_mac, timeout=timeout)
    dhcp_summary = "[DHCP] OK: single entry found." if dhcp_count == 1 else f"[DHCP] WARNING: {dhcp_count} entries found for {nat1_mac} (expected 1)."
    dns_ok, dns_log = _dns_check(fqdn, timeout=timeout)
    dns_summary = "[DNS] OK: A and PTR match FQDN." if dns_ok else "[DNS] WARNING: A/PTR do not both match FQDN."

    # Output block
    rename_section = f"{rename_cmd}\n{r_rename.strip()}" if rename_cmd else ""
    block = f"""

[UMATCH raw]
{umatch_out.strip()}

[CMM Node 1 scan (by BMCIP)]
{cmm_logs.strip()}

{edit_meta}
{r_meta.strip()}
{edit_mac}
{r_mac.strip()}

{rename_section}

{report_cmd}
{report_out.strip()}

# --- DHCP sanity check (expect exactly one) ---
{dhcp_summary}
grep -n -B1 -i '{nat1_mac}' /etc/dhcpd.conf
{dhcp_grep.strip()}

# --- DNS sanity check (A and PTR should resolve to FQDN) ---
{dns_summary}
{dns_log.strip()}
"""
    results[short] = block
    print(f"[COBBLER] Done {short}")
    return results

# --- CLI ---
if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Fix a single Cobbler system (prefer NAT1 from CMM Redfish Node 1) and update a ServiceNow ticket."
    )
    ap.add_argument("--site", default="sc", help="Site code for keyring creds (default: sc)")
    ap.add_argument("--redfish", default=REDFISH_TOOL_DEFAULT,
                    help=f"Path to redfish_mgmt.py (default: {REDFISH_TOOL_DEFAULT})")
    ap.add_argument("--timeout", type=int, default=30, help="Per-command timeout seconds")
    ap.add_argument("--ticket", required=True, help="ServiceNow ticket number to update")
    ap.add_argument("server", help="Single server name (FQDN or short)")
    args = ap.parse_args()

    r = Invoke_FixCobbler_one(
        args.server,
        site=args.site,
        redfish_tool=args.redfish,
        timeout=args.timeout,
    )

    # Console view
    for k, v in r.items():
        print(f"\n--- {k} ---\n{v}")

    # Update ServiceNow
    ok, logs = update_ticket(args.ticket, r)
    print("\n=== ServiceNow update ===")
    print("Status:", "OK" if ok else "FAIL")
    for i, log in enumerate(logs, 1):
        print(f"[chunk {i}] {log}")


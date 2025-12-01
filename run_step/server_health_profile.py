#!/usr/intel/bin/python3
import UsrIntel.R1
try:
    import UsrIntel.R2
except Exception:
    pass

# server_health_profile.py — problems-first JSON for Supermicro nodes
# - Separates BMC vs server NIC:
#     * BMC IP/MAC from CMM Node/1/Network
#     * Server NIC1 MAC + SerialNumber from CMM Node/1/Status (source of truth)
# - Validates SerialNumber vs nodes (umatch)
# - DNS:
#     * short.<dnsdomain> <-> nodes.ipaddr (server IP)
#     * PTR of nodes.ipaddr == short.<dnsdomain>
#     * PTR of mgmt (BMC IP) contains the hostname (short)
# - Keeps BMC/CMM checks; no Cobbler, no PXE/Boot checks.

import argparse, os, re, shlex, socket, subprocess, sys, json, html
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from site_creds import get_site_credentials

IPV4_RE      = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
MAC_RE       = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
TIMEOUT_DEF  = 10
REDFISH_TOOL = os.path.expanduser("~/work/redfish_mgmt_utility/redfish_mgmt.py")
DEFAULT_DNS  = "sc.intel.com"

# Reason codes (for operators); UI should use problems[] for clarity
REASON_DESC = {
    "NO_CREDS"              : "No credentials found for site.",
    "UMATCH_FAIL"           : "Failed to query umatch.",
    "INVALID_MGMT_IP"       : "Invalid or missing management IP.",
    "BMC_UNREACHABLE"       : "BMC TCP:443 unreachable.",
    "BMC_INITIALIZING"      : "BMC manager starting/updating.",
    "POWER_OFF"             : "Power state is off.",
    "BMC_IP_MISMATCH"       : "BMC LAN IP mismatch with umatch.",
    "CMM_NO_IP"             : "CMM returned no IP for bay.",
    "CMM_IP_ZERO"           : "CMM bay IP is 0.0.0.0.",
    "CMM_IP_MISMATCH"       : "CMM bay IP mismatch with umatch.",
    "IPMI_TIMEOUT"          : "ipmitool timed out.",
    "SERIAL_MISMATCH"       : "SerialNumber mismatch between nodes and CMM.",
    "DNS_FWD_MISMATCH"      : "Forward DNS does not match expected IP.",
    "DNS_REVERSE_MISMATCH"  : "Reverse DNS does not match expected hostname.",
    "DNS_MGMT_REVERSE_MISMATCH": "Mgmt IP PTR does not point to hostname.",
    "EXC"                   : "Unhandled exception in checker.",
}

# Which codes make the node "OFFLINE" (hard boot blockers)
HARD_BLOCKERS = {
    "NO_CREDS","UMATCH_FAIL","INVALID_MGMT_IP",
    "BMC_UNREACHABLE","BMC_INITIALIZING","POWER_OFF",
    "BMC_IP_MISMATCH","CMM_NO_IP","CMM_IP_ZERO","CMM_IP_MISMATCH"
}

# ---------- stdout/stderr discipline ----------
def banner(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)

def emit_json(obj) -> None:
    print(json.dumps(obj, separators=(",", ":")), flush=True)

# ---------- small utils ----------
def _short(h: str) -> str:
    return h.split(".", 1)[0].lower()

def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _logfile(s: str) -> str:
    return f"/tmp/server_health_{s}.log"

def _log(s: str, text: str) -> None:
    try:
        with open(_logfile(s), "a", encoding="utf-8") as f:
            f.write(f"[{_ts()}] {text}\n")
    except Exception:
        pass

def _run(s: str, cmd: str, timeout: int, tag: str) -> Tuple[int, str]:
    _log(s, f"[{tag}] $ {cmd}")
    try:
        p = subprocess.run(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=timeout
        )
        out = (p.stdout or "").strip()
        _log(s, f"[{tag}] rc={p.returncode}\n{out}")
        return p.returncode, out
    except subprocess.TimeoutExpired:
        _log(s, f"[{tag}] timeout")
        return 124, f"{tag.lower()}_timeout"

def _tcp(ip: str, port: int, timeout: int = 3) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):  # type: ignore
            return True
    except Exception:
        return False

def _json_parse(txt: str) -> Optional[dict]:
    t = html.unescape(txt or "")
    try:
        start = t.index("{"); end = t.rindex("}") + 1
        return json.loads(t[start:end])
    except Exception:
        return None

def _fqdn(name: str, dnsdomain: str = DEFAULT_DNS) -> str:
    val = (name or "").strip()
    if not val:
        return ""
    return val if "." in val else f"{val}.{dnsdomain}"

# ---------- structured problem helper ----------
def add_problem(problems: List[dict], *, component: str, check: str,
                observed: str = "", expected: str = "", evidence: str = "",
                severity: str = "error", code: str = "", suggestion: str = "") -> None:
    problems.append({
        "component": component,
        "check": check,
        "observed": observed,
        "expected": expected,
        "evidence": evidence,
        "severity": severity,
        "code": code,
        "suggestion": suggestion,
    })

# ---------- wrappers ----------
def _rf_show_node(short: str, host_shortname: str, user: str, pw: str,
                  endpoint: str, timeout: int = 8):
    cmd = f"{shlex.quote(REDFISH_TOOL)} -n {shlex.quote(host_shortname)} --show {shlex.quote(endpoint)} -u {shlex.quote(user)} -p {shlex.quote(pw)}"
    return _run(short, cmd, timeout, "BMC")

def _rf_show_cmm(short: str, enclosure: str, user: str, pw: str,
                 endpoint: str, timeout: int = 8):
    fqdn = _fqdn(enclosure)
    cmd = f"{shlex.quote(REDFISH_TOOL)} -m {shlex.quote(fqdn)} --show {shlex.quote(endpoint)} -u {shlex.quote(user)} -p {shlex.quote(pw)}"
    return _run(short, cmd, timeout, "CMM")

def _rf_show_cmm_status_keys(short: str, enclosure: str, bay: str,
                             user: str, pw: str, timeout: int = 8) -> Tuple[str, str]:
    """
    Use redfish_mgmt.py key filter:
      --show /redfish/v1/Chassis/1/Blade/<bay>/Node/1/Status "NIC1MAC|SerialNumber"
    Returns (nic1_mac, serial_from_status)
    """
    fqdn = _fqdn(enclosure)
    endpoint = f"/redfish/v1/Chassis/1/Blade/{bay}/Node/1/Status"
    keys = "NIC1MAC|SerialNumber"
    cmd = (
        f"{shlex.quote(REDFISH_TOOL)} -m {shlex.quote(fqdn)} "
        f"--show {shlex.quote(endpoint)} {shlex.quote(keys)} "
        f"-u {shlex.quote(user)} -p {shlex.quote(pw)}"
    )
    rc, out = _run(short, cmd, timeout, "CMM")
    nic1 = ""
    serial = ""
    if rc == 0 and out:
        for ln in out.splitlines():
            line = ln.strip()
            if line.startswith("NIC1MAC:"):
                nic1 = line.split(":", 1)[1].strip()
            elif line.startswith("SerialNumber:"):
                serial = line.split(":", 1)[1].strip()

    # fallback to JSON if key-filter output not present
    if not nic1 and not serial:
        rc2, jtxt = _rf_show_cmm(short, enclosure, user, pw, endpoint, timeout)
        if rc2 == 0 and jtxt:
            jobj = _json_parse(jtxt)
            if isinstance(jobj, dict):
                nic1 = str(jobj.get("NIC1MAC", "")).strip()
                serial = str(jobj.get("SerialNumber", "")).strip()

    return nic1, serial

def _ipmi(short: str, bmc_ip: str, user: str, pw: str,
          subcmd: str, timeout: int = 8):
    cmd = f"ipmitool -I lanplus -N 5 -R 2 -H {shlex.quote(bmc_ip)} -U {shlex.quote(user)} -P {shlex.quote(pw)} {subcmd}"
    return _run(short, cmd, timeout, "BMC")

def _umatch_csv(short: str, fields: List[str], timeout: int) -> Dict[str, str]:
    cmd = f"umatch nodes {shlex.quote(short)} -t , {' '.join(map(shlex.quote, fields))}"
    rc, out = _run(short, cmd, timeout, "CORE")
    if rc != 0 or not out:
        return {}
    row = [x.strip() for x in out.split(",")]
    return {fields[i]: (row[i] if i < len(row) else "") for i in range(len(fields))}

# ---------- CMM Node/1/Network (BMC MAC + IP) ----------
def _cmm_node_network_info(txt: str) -> Tuple[str, str]:
    """
    Parse /redfish/v1/Chassis/1/Blade/<bay>/Node/1/Network JSON.
    Returns (bmc_ip, bmc_mac_from_cmm)
    """
    obj = _json_parse(txt)
    if not obj:
        return "", ""
    bmc_ip = ""
    ipv4s = obj.get("IPv4Addresses")
    if isinstance(ipv4s, list):
        for entry in ipv4s:
            if not isinstance(entry, dict):
                continue
            ip = str(entry.get("IPAddress", "")).strip()
            if IPV4_RE.match(ip):
                bmc_ip = ip
                break
    bmc_mac = str(obj.get("MAC Address", "") or obj.get("MACAddress", "")).strip()
    return bmc_ip, bmc_mac

def _get_cmm_bmc_ip_mac(short: str, enclosure: str, bay: str,
                        user: str, pw: str, timeout: int) -> Tuple[str, str, str]:
    """
    Primary: /redfish/v1/Chassis/1/Blade/<bay>/Node/1/Network
    Fallback: /redfish/v1/Managers/1/Oem/Supermicro/BladeNetwork (IP only)
    Returns (cmm_bmc_ip, cmm_bmc_mac, endpoint_used)
    """
    bay = str(bay).strip()
    ep_net  = f"/redfish/v1/Chassis/1/Blade/{bay}/Node/1/Network"
    ep_blade = "/redfish/v1/Managers/1/Oem/Supermicro/BladeNetwork"

    # Node/1/Network
    rc, out = _rf_show_cmm(short, enclosure, user, pw, ep_net, timeout=min(timeout, 10))
    if rc == 0 and out and "Error: 404" not in out:
        ip, mac = _cmm_node_network_info(out)
        if ip or mac:
            return ip, mac, ep_net

    # BladeNetwork fallback (IP only)
    rc2, out2 = _rf_show_cmm(short, enclosure, user, pw, ep_blade, timeout=min(timeout, 10))
    if rc2 == 0 and out2 and "Error: 404" not in out2:
        obj = _json_parse(out2)
        if isinstance(obj, dict) and isinstance(obj.get("IPv4Addresses"), list):
            ipv4s = obj["IPv4Addresses"]
            if ipv4s:
                first = ipv4s[0]
                if isinstance(first, dict):
                    ip = str(first.get("IPAddress", "")).strip()
                    if ip == "N/A":
                        ip = "0.0.0.0"
                    return ip if IPV4_RE.match(ip) else "", "", ep_blade

    return "", "", "no_ip_found"

# ---------- DNS checks ----------
def _dns_checks(short: str, mgmt_ip: str, ipaddr: str, dnsdomain: str,
                problems: List[dict]) -> None:
    """
    DNS logic:
      - FQDN = short + '.' + dnsdomain
      - host <short>               → expected ipaddr
      - host <short>.<dnsdomain>   → expected ipaddr
      - host <ipaddr>              → expected FQDN
      - host <mgmt_ip>             → PTR should at least contain <short>
    """
    fqdn = _fqdn(short, dnsdomain) if dnsdomain else short

    # Forward: host short
    fwd_ips: List[str] = []
    rc_f, out_f = _run(short, f"host {shlex.quote(short)}", 5, "DNS")
    if rc_f == 0 and out_f:
        for ln in out_f.splitlines():
            m = re.search(r"has address\s+(\d+\.\d+\.\d+\.\d+)", ln)
            if m:
                fwd_ips.append(m.group(1))

    if ipaddr and fwd_ips and ipaddr not in fwd_ips:
        add_problem(
            problems,
            component="DNS",
            check="Forward DNS for hostname matches server IP",
            observed=", ".join(fwd_ips),
            expected=ipaddr,
            evidence=f"host {short}",
            severity="warn",
            code="DNS_FWD_MISMATCH",
            suggestion="Update A record for server hostname or nodes.ipaddr."
        )

    # Forward: host fqdn (short.dnsdomain)
    if fqdn and fqdn != short:
        fwd_fqdn_ips: List[str] = []
        rc_ff, out_ff = _run(short, f"host {shlex.quote(fqdn)}", 5, "DNS")
        if rc_ff == 0 and out_ff:
            for ln in out_ff.splitlines():
                m = re.search(r"has address\s+(\d+\.\d+\.\d+\.\d+)", ln)
                if m:
                    fwd_fqdn_ips.append(m.group(1))
        if ipaddr and fwd_fqdn_ips and ipaddr not in fwd_fqdn_ips:
            add_problem(
                problems,
                component="DNS",
                check="Forward DNS for FQDN matches server IP",
                observed=", ".join(fwd_fqdn_ips),
                expected=ipaddr,
                evidence=f"host {fqdn}",
                severity="warn",
                code="DNS_FWD_MISMATCH",
                suggestion="Fix A record for FQDN or nodes.ipaddr."
            )

    # Reverse: host ipaddr (server)
    if ipaddr and IPV4_RE.match(ipaddr):
        rc_rsrv, out_rsrv = _run(short, f"host {shlex.quote(ipaddr)}", 5, "DNS")
        ptr_srv = ""
        if rc_rsrv == 0 and out_rsrv:
            for ln in out_rsrv.splitlines():
                m2 = re.search(r"domain name pointer\s+([^\s]+)", ln)
                if m2:
                    ptr_srv = m2.group(1).rstrip(".")
                    break
        if fqdn and ptr_srv and ptr_srv.lower() != fqdn.lower():
            add_problem(
                problems,
                component="DNS",
                check="Reverse DNS for server IP matches FQDN",
                observed=ptr_srv or "none",
                expected=fqdn,
                evidence=f"host {ipaddr}",
                severity="warn",
                code="DNS_REVERSE_MISMATCH",
                suggestion="Fix PTR for server IP or hostname mapping."
            )

    # Reverse: host mgmt_ip (BMC)
    if mgmt_ip and IPV4_RE.match(mgmt_ip):
        rc_r, out_r = _run(short, f"host {shlex.quote(mgmt_ip)}", 5, "DNS")
        ptr_mgmt = ""
        if rc_r == 0 and out_r:
            for ln in out_r.splitlines():
                m2 = re.search(r"domain name pointer\s+([^\s]+)", ln)
                if m2:
                    ptr_mgmt = m2.group(1).rstrip(".")
                    break
        if ptr_mgmt and short.lower() not in ptr_mgmt.lower():
            add_problem(
                problems,
                component="DNS",
                check="Mgmt IP PTR references hostname",
                observed=ptr_mgmt or "none",
                expected=f"PTR containing '{short}'",
                evidence=f"host {mgmt_ip}",
                severity="warn",
                code="DNS_MGMT_REVERSE_MISMATCH",
                suggestion="Check mgmt PTR; should map to mgmt-<hostname>.<domain>."
            )

# ---------- main per-host check ----------
def check_one(server: str, site: str, timeout: int, verbose: bool) -> Dict:
    short = _short(server)
    try:
        open(_logfile(short), "w").close()
    except Exception:
        pass
    _log(short, f"=== Checking {server} ===")

    full: Dict = {
        "host": server, "short": short,
        "mgmt_ip": "", "console_ip": "", "dnsdomain": "",
        "enclosure": "", "bay": "",
        "bmc": {}, "cmm": {},
        "reasons": [], "error_codes": [],
        "overall": "UNKNOWN",
        "logfile": _logfile(short),
    }
    problems: List[dict] = []

    creds = get_site_credentials(site)
    if not creds:
        add_problem(
            problems,
            component="CORE",
            check="Site credentials available",
            observed="none",
            expected="valid credentials",
            evidence="get_site_credentials(site)",
            severity="error",
            code="NO_CREDS",
            suggestion="Verify site credential configuration."
        )
        full["overall"] = "OFFLINE"
        return _render(full, problems, verbose)

    # umatch: include serialnum + macaddr + ipaddr for nodes view
    fields = ["mgmt","console","dnsdomain","enclosure","bay","serialnum","macaddr","ipaddr"]
    um = _umatch_csv(short, fields, timeout)
    if not um:
        add_problem(
            problems,
            component="CORE",
            check="umatch lookup",
            observed="failed",
            expected="host metadata row",
            evidence="umatch nodes <short>",
            severity="error",
            code="UMATCH_FAIL",
            suggestion="Check umatch/CMDB for this host."
        )
        full["overall"] = "OFFLINE"
        return _render(full, problems, verbose)

    mgmt      = (um.get("mgmt","") or "").strip()
    console   = (um.get("console","") or "").strip()
    dnsdomain = (um.get("dnsdomain","") or "").strip()
    enclosure = (um.get("enclosure","") or "").strip()
    bay       = (um.get("bay","") or "").strip()
    nodes_sn  = (um.get("serialnum","") or "").strip()
    nodes_mac = (um.get("macaddr","") or "").strip()
    nodes_ip  = (um.get("ipaddr","") or "").strip()

    full["mgmt_ip"]   = mgmt
    full["console_ip"]= console
    full["dnsdomain"] = dnsdomain
    full["enclosure"] = enclosure
    full["bay"]       = bay

    if not mgmt or mgmt == "0.0.0.0" or not IPV4_RE.match(mgmt):
        add_problem(
            problems,
            component="CORE",
            check="Management IP validity",
            observed=mgmt or "empty",
            expected="IPv4 address",
            evidence="umatch.mgmt",
            severity="error",
            code="INVALID_MGMT_IP",
            suggestion="Fix BMC IP in inventory or CMM."
        )
        full["overall"] = "OFFLINE"
        return _render(full, problems, verbose)

    # BMC TLS reachability
    https_ok = _tcp(mgmt, 443, timeout=3)
    if not https_ok:
        add_problem(
            problems,
            component="BMC",
            check="HTTPS reachable (TCP/443)",
            observed="closed",
            expected="open",
            evidence=f"tcp_connect {mgmt}:443",
            severity="error",
            code="BMC_UNREACHABLE",
            suggestion="Check network/VLAN/firewall to BMC."
        )

    rf_user, rf_pw = creds[0]

    # Redfish Manager/System
    mgr_state = ""
    power_state = ""

    rc_m, out_m = _rf_show_node(short, short, rf_user, rf_pw, "/redfish/v1/Managers/1", timeout=min(timeout, 8))
    if rc_m == 0 and out_m:
        mobj = _json_parse(out_m)
        if isinstance(mobj, dict):
            st = mobj.get("Status", {})
            if isinstance(st, dict):
                mgr_state = str(st.get("State", "")).strip()

    rc_s, out_s = _rf_show_node(short, short, rf_user, rf_pw, "/redfish/v1/Systems/1", timeout=min(timeout, 8))
    if rc_s == 0 and out_s:
        sobj = _json_parse(out_s)
        if isinstance(sobj, dict):
            power_state = str(sobj.get("PowerState", "")).strip()

    if mgr_state.lower() in ("starting","updating"):
        add_problem(
            problems,
            component="BMC",
            check="Manager state",
            observed=mgr_state or "unknown",
            expected="Enabled",
            evidence="/redfish/v1/Managers/1.Status.State",
            severity="error",
            code="BMC_INITIALIZING",
            suggestion="Wait/reset BMC until state is Enabled."
        )

    if power_state and power_state.lower() != "on":
        add_problem(
            problems,
            component="BMC",
            check="Power state",
            observed=power_state or "unknown",
            expected="On",
            evidence="/redfish/v1/Systems/1.PowerState",
            severity="error",
            code="POWER_OFF",
            suggestion="Power on or check PSU/policy."
        )

    # IPMI lan print -> BMC LAN IP
    bmc_lan_ip = ""
    rc_ipmi, out_ipmi = _ipmi(short, mgmt, rf_user, rf_pw, "lan print", timeout=min(timeout, 8))
    if rc_ipmi == 0 and out_ipmi:
        for ln in out_ipmi.splitlines():
            if ln.strip().startswith("IP Address") and ":" in ln:
                candidate = ln.split(":", 1)[1].strip()
                if IPV4_RE.match(candidate):
                    bmc_lan_ip = candidate
                    break
    elif rc_ipmi == 124:
        add_problem(
            problems,
            component="BMC",
            check="IPMI responsiveness",
            observed="timeout",
            expected="response within 8s",
            evidence="ipmitool lan print",
            severity="warn",
            code="IPMI_TIMEOUT",
            suggestion="Check BMC load or network to BMC."
        )

    if bmc_lan_ip and bmc_lan_ip != mgmt:
        add_problem(
            problems,
            component="BMC",
            check="BMC LAN IP matches umatch.mgmt",
            observed=bmc_lan_ip,
            expected=mgmt,
            evidence="ipmitool lan print vs umatch.mgmt",
            severity="error",
            code="BMC_IP_MISMATCH",
            suggestion="Align BMC configuration with inventory."
        )

    # CMM: BMC IP/MAC from Node/1/Network + server NIC1MAC + Serial from Node/1/Status
    cmm_bmc_ip = ""
    cmm_bmc_mac = ""
    cmm_ep = ""
    nic1_mac = ""
    status_sn = ""

    if enclosure and bay:
        cmm_bmc_ip, cmm_bmc_mac, cmm_ep = _get_cmm_bmc_ip_mac(short, enclosure, bay, rf_user, rf_pw, timeout)
        nic1_mac, status_sn = _rf_show_cmm_status_keys(short, enclosure, bay, rf_user, rf_pw, timeout=min(timeout, 8))

        # SerialNumber check (Node/1/Status vs nodes)
        if nodes_sn and status_sn and nodes_sn != status_sn:
            add_problem(
                problems,
                component=f"CMM bay {bay} @ {_fqdn(enclosure)}",
                check="SerialNumber matches nodes.serialnum",
                observed=status_sn,
                expected=nodes_sn,
                evidence="/redfish/v1/Chassis/1/Blade/<bay>/Node/1/Status",
                severity="warn",
                code="SERIAL_MISMATCH",
                suggestion="Confirm mapping; may be wrong bay or stale nodes entry."
            )

        # CMM bay IP vs mgmt
        if not cmm_bmc_ip:
            add_problem(
                problems,
                component=f"CMM bay {bay} @ {_fqdn(enclosure)}",
                check="CMM bay IP present",
                observed="absent",
                expected="IPv4 address",
                evidence=cmm_ep,
                severity="error",
                code="CMM_NO_IP",
                suggestion="Set bay IP in CMM."
            )
        elif cmm_bmc_ip == "0.0.0.0":
            add_problem(
                problems,
                component=f"CMM bay {bay} @ {_fqdn(enclosure)}",
                check="CMM bay IP not zero",
                observed="0.0.0.0",
                expected="valid IPv4",
                evidence=cmm_ep,
                severity="error",
                code="CMM_IP_ZERO",
                suggestion="Configure non-zero IP for bay."
            )
        elif cmm_bmc_ip != mgmt:
            add_problem(
                problems,
                component=f"CMM bay {bay} @ {_fqdn(enclosure)}",
                check="CMM bay IP matches umatch.mgmt",
                observed=cmm_bmc_ip,
                expected=mgmt,
                evidence=cmm_ep,
                severity="error",
                code="CMM_IP_MISMATCH",
                suggestion="Sync CMM bay mapping to BMC mgmt IP."
            )

    # DNS checks (server + mgmt)
    _dns_checks(short, mgmt, nodes_ip, dnsdomain, problems)

    # Fill verbose BMC/CMM summary
    full["bmc"] = {
        "https_ok": https_ok,
        "mgr_state": mgr_state or "",
        "power_state": power_state or "",
        "lan_ip": bmc_lan_ip or "",
        "nodes_serialnum": nodes_sn or "",
        "nodes_macaddr": nodes_mac or "",
        "nodes_ipaddr": nodes_ip or "",
        "nic1_mac": nic1_mac or "",
        "status_serialnum": status_sn or "",
    }
    full["cmm"] = {
        "ip": cmm_bmc_ip or "",
        "bmc_mac": cmm_bmc_mac or "",
        "endpoint": cmm_ep or "",
    }

    # Compute overall from hard blockers
    codes = [p.get("code","") for p in problems if p.get("code")]
    hard = any(c in HARD_BLOCKERS for c in codes)
    full["overall"] = "OFFLINE" if hard else "ONLINE"
    full["error_codes"] = codes
    full["reasons"] = [
        {"code": c, "scope": "N/A", "short": REASON_DESC.get(c, c), "details": ""}
        for c in codes
    ]

    # human-friendly summary in logfile
    try:
        lines = []
        lines.append("=== Summary ===")
        lines.append(f"Overall: {full['overall']}")
        if problems:
            lines.append("Problems:")
            for p in problems:
                lines.append(
                    f" - [{p.get('component')}] {p.get('check')}: "
                    f"observed={p.get('observed')} expected={p.get('expected')} "
                    f"({p.get('code')})"
                )
        else:
            lines.append(" - none")
        with open(_logfile(short), "a", encoding="utf-8") as f:
            f.write("\n" + "\n".join(lines) + "\n")
    except Exception:
        pass

    return _render(full, problems, verbose)

# ---------- render minimal vs verbose ----------
def _render(full: Dict, problems: List[dict], verbose: bool) -> Dict:
    base = {
        "host": full.get("short") or full.get("host"),
        "mgmt_ip": full.get("mgmt_ip",""),
        "overall": full.get("overall","UNKNOWN"),
        "problems": problems,
    }
    if verbose:
        base["details"] = {
            "console_ip": full.get("console_ip",""),
            "dnsdomain": full.get("dnsdomain",""),
            "enclosure": full.get("enclosure",""),
            "bay": full.get("bay",""),
            "bmc": full.get("bmc",{}),
            "cmm": full.get("cmm",{}),
            "error_codes": full.get("error_codes",[]),
            "logfile": full.get("logfile",""),
        }
    return base

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(
        description="Server health profile for Supermicro — problems-first JSON"
    )
    ap.add_argument("--site", default="sc")
    ap.add_argument("--timeout", type=int, default=TIMEOUT_DEF)
    ap.add_argument("--verbose", action="store_true",
                    help="Include detailed metadata (BMC/CMM, serials, MACs, DNS).")
    ap.add_argument("servers", nargs="+", help="Hostnames (short or FQDN)")
    args = ap.parse_args()

    results: List[Dict] = []
    for s in args.servers:
        try:
            res = check_one(s, site=args.site, timeout=args.timeout, verbose=args.verbose)
            results.append(res)
            banner(f"[log] {_short(s)} -> {_logfile(_short(s))}")
        except Exception as e:
            short = _short(s)
            problems = [{
                "component": "CORE",
                "check": "Unhandled exception",
                "observed": str(e),
                "expected": "no exception",
                "evidence": "",
                "severity": "error",
                "code": "EXC",
                "suggestion": "Inspect logs and recent changes.",
            }]
            out = {
                "host": short,
                "mgmt_ip": "",
                "overall": "OFFLINE",
                "problems": problems,
            }
            if args.verbose:
                out["details"] = {"logfile": _logfile(short)}
            results.append(out)

    emit_json(results[0] if len(results) == 1 else results)

if __name__ == "__main__":
    main()


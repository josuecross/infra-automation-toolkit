#!/usr/intel/bin/python3
import UsrIntel.R1
try:
    import UsrIntel.R2
except Exception:
    pass

import os, subprocess
from typing import Dict, List, Tuple

# Resolve the absolute path to sn_cli.py and the Python interpreter
SN_CLI = os.path.expanduser(os.path.expandvars("$HOME/ServiceNowCloud/sn_cli.py"))

def _run_argv(argv: List[str], timeout: int = 120) -> Tuple[int, str]:
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=timeout)
    return p.returncode, p.stdout

def _dict_to_notes(results: Dict[str, str]) -> str:
    lines = ["=== AutoOps Results ==="]
    for host, block in results.items():
        lines.append(f"\n--- {host} ---")
        lines.append(block.rstrip() if block is not None else "(no output)")
    return "\n".join(lines)

def _chunk(s: str, limit: int = 9000) -> List[str]:
    if len(s) <= limit:
        return [s]
    out, cur, cur_len = [], [], 0
    for line in s.splitlines(True):
        if cur_len + len(line) > limit:
            out.append("".join(cur))
            cur, cur_len = [], 0
        cur.append(line); cur_len += len(line)
    if cur:
        out.append("".join(cur))
    return out

def update_ticket(ticket_id: str, results: Dict[str, str], chunk_limit: int = 9000) -> Tuple[bool, List[str]]:
    """
    Posts work_notes updates to a ServiceNow ticket using sn_cli.py.
    Returns (ok, logs) where logs is a list of CLI outputs (one per chunk).
    """
    # Sanity check early (better error than FileNotFoundError from subprocess)
    if not os.path.isfile(SN_CLI):
        raise FileNotFoundError(f"sn_cli.py not found at {SN_CLI}")

    notes  = _dict_to_notes(results)
    chunks = _chunk(notes, limit=chunk_limit)

    logs: List[str] = []
    all_ok = True
    for idx, chunk in enumerate(chunks, 1):
        # Invoke via python so we don't rely on executable bits or shebang path
        argv = [
            SN_CLI,
            "-update",                # keep the flag your ArgsParser expects
            "--ticket_id", str(ticket_id),
            "--work_notes", chunk,    # passed as a single arg; no shell needed
        ]
        rc, out = _run_argv(argv)
        logs.append(out.strip())
        if rc != 0:
            all_ok = False
    return all_ok, logs

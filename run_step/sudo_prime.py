#!/usr/intel/bin/python3
import UsrIntel.R1  # Intel BKM: must be first
try:
    import UsrIntel.R2
except Exception:
    pass

# sudo_prime.py
import os
import pathlib
import subprocess
from typing import Tuple

import keyring
from keyrings.alt.file import EncryptedKeyring


def _bind_keyring(
    master_path: str = "~/.keyring-master",
    crypt_path: str = "~/.local/share/python_keyring/crypted_pass.cfg",
) -> None:
    """Bind encrypted keyring so keyring.get_password() won't prompt."""
    mp = pathlib.Path(master_path).expanduser()
    if not mp.exists():
        raise RuntimeError(f"Master file not found: {mp}")
    master = mp.read_text()
    cp = pathlib.Path(crypt_path).expanduser()
    cp.parent.mkdir(parents=True, exist_ok=True)

    kr = EncryptedKeyring()
    kr.file_path = str(cp)
    kr.keyring_key = master
    keyring.set_keyring(kr)


def _run(cmd: str, timeout: int = 10) -> Tuple[int, str]:
    p = subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    return p.returncode, p.stdout


def prime_sudo(
    *,
    keyring_service: str = "sudo",
    keyring_user: str = None,
    allocate_tty: bool = False,
) -> Tuple[str, str]:
    """
    Ensure 'sudo' timestamp is primed for the current user (local box).
    - First tries 'sudo -n true' (no prompt).
    - If not primed, reads sudo password from keyring (service=keyring_service, user=keyring_user or $USER)
      and runs: echo <pw> | sudo -S -p '' -v
    Returns: ('ok'|'fail', combined_output)
    """
    # 1) Already primed?
    rc, out = _run("sudo -n true 2>/dev/null || true")
    if rc == 0:
        return "ok", "[SUDO] Already primed."

    # 2) Bind keyring + fetch password
    _bind_keyring()
    user = keyring_user or os.environ.get("USER") or "default"
    pw = keyring.get_password(keyring_service, user)
    if not pw:
        return "fail", f"[SUDO][FAIL] No sudo password stored in keyring (service='{keyring_service}', user='{user}')."

    # 3) Prime with password
    # Optional TTY allocation rarely needed locally; we keep a variant if enforced by sudoers.
    if allocate_tty:
        # This mirrors the PS 'requiretty' behavior if ever needed.
        cmd = "bash -lc " + shq("echo {pw} | sudo -S -p '' -v && sudo -n true && echo PRIMED || echo FAIL".format(pw=pw))
    else:
        cmd = "echo {pw} | sudo -S -p '' -v && sudo -n true && echo PRIMED || echo FAIL".format(pw=shq_lit(pw))

    rc2, out2 = _run(cmd, timeout=10)
    status = "ok" if ("PRIMED" in out2 or rc2 == 0) else "fail"
    return status, out2


def shq(s: str) -> str:
    """Single-quote for bash -lc wrapping."""
    return "'" + s.replace("'", "'\"'\"'") + "'"


def shq_lit(s: str) -> str:
    """Minimal escaping for echo pipeline."""
    return s.replace("\\", "\\\\").replace("$", "\\$").replace("`", "\\`")


#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Keyring diagnostic for headless environments.

- Collects environment, versions, backend, config and file permissions.
- Verifies encrypted file backend (keyrings.alt.file.EncryptedKeyring).
- Tests Python API set/get (non-interactive).
- Tests keyring CLI get with timeouts (detects "prompting" vs "works").
- Writes detailed log to ./kr_diagnose.log; prints a brief summary.

Usage:
  python kr_diagnose.py --service sc --user remadm --master "$PYTHON_KEYRING_PASSWORD"
"""

import argparse
import getpass
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

LOG_PATH = Path("./kr_diagnose.log")


def mask_secret(s: str, keep: int = 2) -> str:
    if not s:
        return ""
    if len(s) <= keep:
        return "*" * len(s)
    return "*" * (len(s) - keep) + s[-keep:]


def log(msg: str):
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {msg}\n")


def perm_string(p: Path) -> str:
    try:
        st = p.stat()
    except FileNotFoundError:
        return "MISSING"
    mode = stat.S_IMODE(st.st_mode)
    return oct(mode)


def run_cmd(cmd, env=None, timeout=3):
    try:
        r = subprocess.run(
            cmd,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            timeout=timeout,
            check=False,
        )
        return ("ok", r.returncode, r.stdout.decode(errors="replace"))
    except subprocess.TimeoutExpired as e:
        return ("timeout", None, (e.stdout or b"").decode(errors="replace"))
    except Exception as e:
        return ("error", None, f"{type(e).__name__}: {e}")


def main():
    # Fresh log
    LOG_PATH.write_text("", encoding="utf-8")

    ap = argparse.ArgumentParser()
    ap.add_argument("--service", required=True, help="Keyring service name (e.g., site code)")
    ap.add_argument("--user", required=True, help="Keyring username (e.g., bmc user)")
    ap.add_argument("--master", default=None, help="Master password to unlock encrypted keyring")
    ap.add_argument("--cryptfile-path", default=None, help="Path to crypted_pass.cfg (optional)")
    ap.add_argument("--cli-timeout", type=float, default=3.0, help="Seconds to wait for CLI before declaring prompt/timeout")
    ap.add_argument("--no-cli", action="store_true", help="Skip CLI tests and only use Python API")
    args = ap.parse_args()

    service = args.service
    user = args.user
    master = args.master
    cryptfile_path_env = args.cryptfile_path

    # ---- Environment snapshot
    log("=== Environment ===")
    uname = platform.uname()
    env_info = {
        "python": sys.version,
        "executable": sys.executable,
        "platform": platform.platform(),
        "uname": dict(system=uname.system, node=uname.node, release=uname.release, version=uname.version, machine=uname.machine),
        "cwd": str(Path.cwd()),
        "PATH_contains_keyring": bool(shutil.which("keyring")),
        "which_keyring": shutil.which("keyring") or "",
    }
    log(json.dumps(env_info, indent=2))

    # Capture env vars (masked)
    env_vars = {
        "PYTHON_KEYRING_BACKEND": os.environ.get("PYTHON_KEYRING_BACKEND"),
        "PYTHON_KEYRING_PASSWORD": mask_secret(os.environ.get("PYTHON_KEYRING_PASSWORD")),
        "KEYRING_CRYPTFILE_PASSWORD": mask_secret(os.environ.get("KEYRING_CRYPTFILE_PASSWORD")),
        "KEYRING_PASS": mask_secret(os.environ.get("KEYRING_PASS")),
        "KEYRING_CRYPTFILE_PATH": os.environ.get("KEYRING_CRYPTFILE_PATH"),
        "HOME": os.environ.get("HOME"),
    }
    log("Env vars (masked): " + json.dumps(env_vars, indent=2))

    # If --master provided, set env for this run
    if master:
        os.environ["PYTHON_KEYRING_PASSWORD"] = master
        os.environ["KEYRING_CRYPTFILE_PASSWORD"] = master
        log("Applied master password from --master (masked): " + mask_secret(master))

    # Default cryptfile path (if not set)
    default_crypt_path = str(Path.home() / ".local/share/python_keyring/crypted_pass.cfg")
    if cryptfile_path_env:
        os.environ["KEYRING_CRYPTFILE_PATH"] = cryptfile_path_env
        crypt_path = Path(cryptfile_path_env)
    else:
        crypt_path = Path(os.environ.get("KEYRING_CRYPTFILE_PATH") or default_crypt_path)

    # ---- Keyring/Backend info
    log("=== Python packages / backend ===")
    try:
        import keyring
        kr_ver = getattr(keyring, "__version__", "unknown")
    except Exception as e:
        log(f"ERROR importing keyring: {e}")
        print("? Could not import keyring. See kr_diagnose.log")
        return

    try:
        import keyrings.alt  # noqa
        kra_ver = getattr(sys.modules["keyrings.alt"], "__version__", "unknown")
    except Exception as e:
        kra_ver = f"import_error: {e}"

    # pycryptodomex / pycryptodome presence
    crypto_flags = {}
    try:
        import Cryptodome  # noqa
        crypto_flags["Cryptodome"] = True
    except Exception as e:
        crypto_flags["Cryptodome"] = f"missing: {e}"
    try:
        import Crypto  # noqa
        crypto_flags["Crypto"] = True
    except Exception as e:
        crypto_flags["Crypto"] = f"missing: {e}"

    backend_obj = keyring.get_keyring()
    log(json.dumps({
        "keyring_version": kr_ver,
        "keyrings.alt_version": kra_ver,
        "backend_str": str(backend_obj),
        "backend_class": backend_obj.__class__.__name__,
        "crypto_modules": crypto_flags,
    }, indent=2))

    # keyringrc content (if present)
    rc_path = Path.home() / ".config/python_keyring/keyringrc.cfg"
    log("=== keyringrc.cfg ===")
    if rc_path.exists():
        try:
            content = rc_path.read_text(encoding="utf-8", errors="replace")
            log(f"keyringrc.cfg path: {rc_path}\n" + content)
        except Exception as e:
            log(f"ERROR reading {rc_path}: {e}")
    else:
        log(f"keyringrc.cfg not found at {rc_path}")

    # cryptfile path/permissions
    log("=== Encrypted key file ===")
    log(f"Crypt path (resolved): {crypt_path}")
    if crypt_path.exists():
        log(f"Crypt file perms: {perm_string(crypt_path)}")
        log(f"Parent perms: {perm_string(crypt_path.parent)}")
    else:
        log("Crypt file does not exist yet (it will be created on first write)")

    # ---- Python API test
    log("=== Python API test ===")
    ok_read = False
    try:
        pw = keyring.get_password(service, user)
        ok_read = pw is not None
        log(f"Python get_password(service={service}, user={user}) -> {'FOUND' if ok_read else 'MISSING'} (length={len(pw) if pw else 0})")
    except Exception as e:
        log(f"ERROR get_password: {type(e).__name__}: {e}")

    # If missing, try to store (prompt for BMC pw) and read back.
    # We only prompt if running in a TTY; otherwise skip interactive prompt.
    stored_now = False
    if not ok_read:
        if sys.stdin.isatty():
            try:
                bmc_pw = getpass.getpass(f"Enter BMC password for {service}/{user} (will be stored encrypted): ")
                if bmc_pw:
                    import keyring
                    keyring.set_password(service, user, bmc_pw)
                    stored_now = True
                    pw2 = keyring.get_password(service, user)
                    log(f"After set_password, get_password -> {'FOUND' if bool(pw2) else 'MISSING'} (len={len(pw2) if pw2 else 0})")
                else:
                    log("User left BMC password empty; skipping set.")
            except Exception as e:
                log(f"ERROR set_password: {type(e).__name__}: {e}")
        else:
            log("Non-interactive session; skipping interactive BMC-password prompt.")

    # ---- CLI tests (optional)
    if not args.no_cli:
        log("=== CLI tests ===")
        # 1) `keyring --list-backends`
        status, rc, out = run_cmd(["keyring", "--list-backends"], timeout=args.cli_timeout)
        log(f"CLI list-backends -> status={status} rc={rc}\n{out}")

        # 2) Try `keyring get service user` with our env (should not prompt; we use timeout)
        env = os.environ.copy()
        status, rc, out = run_cmd(["keyring", "get", service, user], env=env, timeout=args.cli_timeout)
        log(f"CLI get ({service}, {user}) -> status={status} rc={rc}\n{out}")
        if status == "timeout":
            log("Interpretation: CLI likely prompting for master password (or hanging).")
        elif status == "ok" and rc == 0:
            log("CLI get succeeded without prompting.")
        else:
            log("CLI get returned error; see output above.")

    # ---- Summary to console
    print("=== Keyring Diagnose Summary ===")
    print(f"- Python: {platform.python_version()}  | keyring {kr_ver} | keyrings.alt {kra_ver}")
    print(f"- Backend: {backend_obj} (class: {backend_obj.__class__.__name__})")
    print(f"- Encrypted file: {crypt_path}  [{ 'exists' if crypt_path.exists() else 'will create on write' }]")
    print(f"- Python API get_password({service}, {user}): {'FOUND' if ok_read or stored_now else 'MISSING'}")
    if not args.no_cli:
        print(f"- CLI tests: see {LOG_PATH.name} for timeout/errors indicating master prompt")
    print(f"\nDetailed log written to: {LOG_PATH.resolve()}")
    print("If Python API shows FOUND but CLI times out or errors, prefer Python (non-interactive) in jobs.")
    print("To force non-interactive unlock, export:")
    print("  export PYTHON_KEYRING_BACKEND=keyrings.alt.file.EncryptedKeyring")
    print("  export PYTHON_KEYRING_PASSWORD='<master>'  # and/or KEYRING_CRYPTFILE_PASSWORD")
    print("  export KEYRING_CRYPTFILE_PATH=\"$HOME/.local/share/python_keyring/crypted_pass.cfg\"")


if __name__ == "__main__":
    main()

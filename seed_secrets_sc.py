#!/usr/intel/bin/python3
import UsrIntel.R1  # MUST be the first import per BKM
try:
    import UsrIntel.R2  # optional: use newer release if present
except Exception:
    pass

# seed_secrets.py  (run interactively once)
import pathlib
import getpass
import keyring
from keyrings.alt.file import EncryptedKeyring


def bind_keyring(
    master_path="~/.keyring-master",
    crypt_path="~/.local/share/python_keyring/crypted_pass.cfg",
):
    mp = pathlib.Path(master_path).expanduser()
    if not mp.exists():
        raise SystemExit(f"Master file not found: {mp}")
    master = mp.read_text()

    cp = pathlib.Path(crypt_path).expanduser()
    cp.parent.mkdir(parents=True, exist_ok=True)

    kr = EncryptedKeyring()
    kr.file_path = str(cp)
    kr.keyring_key = master
    keyring.set_keyring(kr)
    return cp


def main():
    cryptfile = bind_keyring()
    # Edit this list or load from your own site_users.conf
    PAIRS = [
        ("sc", "remadm"),
        ("sc", "admin"),
        ("sc", "logistics"),
        ("sc", "Administrator"),
        ("sc", "vendor"),
        ("sc", "dcmuser"),
    ]
    for site, user in PAIRS:
        pw = getpass.getpass(f"Enter BMC password for {site}/{user}: ")
        keyring.set_password(site, user, pw)
        print(f"Stored {site}/{user}")
    print(f"\nAll set. Encrypted keyring: {cryptfile}")


if __name__ == "__main__":
    main()

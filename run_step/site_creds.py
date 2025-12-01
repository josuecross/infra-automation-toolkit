#!/usr/intel/bin/python3
import UsrIntel.R1  # must be the first import per BKM; falls back below if needed

# site_creds.py
# Returns credentials for a site in the order you want to try them.
# Passwords are pulled from your encrypted keyring (seeded already).

import os
import pathlib
from typing import List, Tuple

import keyring
from keyrings.alt.file import EncryptedKeyring

# Default username order (edit if needed)
DEFAULT_USERS = [
    "remadm",
    "admin",
    "logistics",
    "Administrator",
    "vendor",
    "dcmuser",
]

def _bind_keyring(
    master_path: str = "~/.keyring-master",
    crypt_path: str = "~/.local/share/python_keyring/crypted_pass.cfg",
) -> None:
    """
    Bind EncryptedKeyring with master from ~/.keyring-master (no prompts at runtime).
    """
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

def get_site_credentials(site: str, users: List[str] = None) -> List[Tuple[str, str]]:
    """
    Return list of (user, password) for given site, in order.
    Skips users that have no stored password.
    """
    _bind_keyring()
    order = users or DEFAULT_USERS
    creds: List[Tuple[str, str]] = []
    for u in order:
        pw = keyring.get_password(site, u)
        if pw:
            creds.append((u, pw))
    return creds

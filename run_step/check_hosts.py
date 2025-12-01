#!/usr/intel/bin/python3
import UsrIntel.R1  # Intel BKM: must be first
try:
    import UsrIntel.R2
except Exception:
    pass

import socket
import sys
import subprocess
import csv


def ping_check(host: str, timeout: int = 1) -> bool:
    """Return True if host responds to ping."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception:
        return False


def tcp_check(host: str, port: int = 22, timeout: int = 3) -> bool:
    """Return True if TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <host1> [host2 host3 ...]")
        sys.exit(1)

    hosts = sys.argv[1:]
    writer = csv.writer(sys.stdout)
    writer.writerow(["Host", "Status"])

    for host in hosts:
        is_ping_ok = ping_check(host)
        is_ssh_ok = tcp_check(host, 22)
        status = "ONLINE" if is_ping_ok and is_ssh_ok else "OFFLINE"
        writer.writerow([host, status])


if __name__ == "__main__":
    main()

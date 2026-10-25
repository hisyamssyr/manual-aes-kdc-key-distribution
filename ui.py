import sys
import threading
from typing import Any


OUTPUT_LOCK = threading.Lock()
_active_prompt: str = ""
_unread_count: int = 0


def set_unread(count: int) -> None:
    global _unread_count
    with OUTPUT_LOCK:
        _unread_count = max(0, count)


def print_info(text: str) -> None:
    with OUTPUT_LOCK:
        print(f"[INFO] {text}")


def print_error(text: str) -> None:
    with OUTPUT_LOCK:
        print(f"[ERROR] {text}")


def print_incoming(record: dict[str, Any]) -> None:
    from_id = str(record.get("from", "unknown"))
    plaintext = str(record.get("plaintext", ""))
    ct_hex = str(record.get("ct", ""))

    with OUTPUT_LOCK:
        is_tty = sys.stdout.isatty() and sys.stdin.isatty()
        header = f"[PESAN MASUK] dari {from_id}:"
        body_plain = f"  Plaintext : {plaintext}"
        body_cipher = f"  Ciphertext: {ct_hex}"

        if is_tty and _active_prompt:
            sys.stdout.write(f"\r\033[K{header}\n{body_plain}\n{body_cipher}\n{_active_prompt}")
            sys.stdout.flush()
        else:
            print(header)
            print(body_plain)
            print(body_cipher)


def prompt_input(label: str) -> str:
    global _active_prompt
    with OUTPUT_LOCK:
        _active_prompt = label
    try:
        return input(label).rstrip("\r\n")
    finally:
        with OUTPUT_LOCK:
            _active_prompt = ""


def render_status(
    role: str,
    identity: str,
    peer_id: str,
    state: str,
    kcv: str = "-",
    unread: int = 0,
    last_error: str = "-",
) -> None:
    with OUTPUT_LOCK:
        print("\n=== STATUS SESI ===")
        print(f"Role         : {role.upper()}")
        print(f"ID           : {identity}")
        print(f"Peer ID      : {peer_id}")
        print(f"State        : {state}")
        print(f"KCV Ks       : {kcv}")
        print(f"Pesan Belum  : {unread}")
        print(f"Error Terkait: {last_error}")

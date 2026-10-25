import argparse
import getpass
import logging
import sys
from typing import Any

from app_logging import RingBufferHandler, capture_config_warnings, configure_logging, flush_config_warnings
from config import ConfigError, load_config
from encoding_utils import validate_key
from network import NetworkError, close_socket, connect, recv_message, send_message
from protocol import (
    ProtocolError,
    build_kdc_request,
    compute_kcv,
    new_nonce,
    open_kdc_response,
)
from session import AliceSession, AliceState, StateError


MAX_KEY_PROMPT_ATTEMPTS = 3


def request_session_key(
    config: dict[str, Any],
    ka: bytes,
    session: AliceSession | None = None,
    logger: logging.Logger | None = None,
) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(ka, bytes):
        raise ValueError("ka must be bytes")
    validate_key(ka.decode("ascii"))

    if session is None:
        session = AliceSession()

    if session.state not in (AliceState.IDLE, AliceState.KEY_READY):
        raise StateError(f"cannot request session key from state: {session.state.value}")

    n1 = new_nonce()
    session.begin_request(n1)

    connect_timeout = float(config.get("timeouts", {}).get("connect", 5.0))
    step_timeout = float(config.get("timeouts", {}).get("step", 10.0))
    sock = None

    try:
        sock = connect(config["kdc"]["host"], config["kdc"]["port"], timeout=connect_timeout)
        send_message(sock, build_kdc_request(config["id"], config["peer_id"], n1))
        resp = recv_message(sock, timeout=step_timeout)

        if resp.get("type") == "KDC_ERR":
            code = str(resp.get("code", "BAD_FORMAT"))
            raise ProtocolError(code, str(resp.get("msg", code)))

        ks, ticket = open_kdc_response(resp, ka, config["id"], config["peer_id"], n1)
        session.finish_request_success(ks, ticket)
        if logger is not None:
            logger.info("session key obtained", extra={"event": "KDC_SUCCESS", "peer_id": config["peer_id"]})
        return ks, ticket
    except (NetworkError, ProtocolError, Exception):
        session.reset_to_idle()
        if logger is not None:
            logger.warning("request session key failed", extra={"event": "KDC_ERROR", "peer_id": config["peer_id"]})
        raise
    finally:
        if sock is not None:
            close_socket(sock)


def prompt_ka() -> bytes:
    for _ in range(MAX_KEY_PROMPT_ATTEMPTS):
        try:
            first = getpass.getpass("Master Key Alice (Ka) (16 karakter ASCII): ")
            confirm = getpass.getpass("Konfirmasi Master Key Alice (Ka): ")
            if first != confirm:
                print("Key tidak cocok, silakan coba lagi.", file=sys.stderr)
                continue
            return validate_key(first)
        except ValueError as err:
            print(f"Key tidak valid: {err}", file=sys.stderr)
    print("Gagal memasukkan key setelah 3 percobaan.", file=sys.stderr)
    sys.exit(2)


def run_interactive_menu(
    config: dict[str, Any],
    initial_ka: bytes,
    session: AliceSession,
    logger: logging.Logger,
    ring_buffer: RingBufferHandler,
) -> None:
    ka = initial_ka
    menu = "\n--- MENU ALICE ---\n[1] Minta Ks ke KDC\n[2] Status Sesi & KCV\n[3] Ubah Ka\n[4] Log Aktivitas\n[0] Keluar\nPilih: "

    while True:
        try:
            choice = input(menu).strip()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "1":
            try:
                ks, _ = request_session_key(config, ka, session, logger)
                print(f"Berhasil! State: {session.state.value} | KCV Ks: {compute_kcv(ks)}")
            except ProtocolError as err:
                print(f"Protokol error: {err.code}")
            except Exception as err:
                print(f"Gagal memperoleh session key: {err}")
        elif choice == "2":
            ks_kcv = compute_kcv(session.ks) if session.ks else "(belum ada)"
            print(f"State: {session.state.value} | KCV Ka: {compute_kcv(ka)} | KCV Ks: {ks_kcv}")
        elif choice == "3":
            ka = prompt_ka()
            session.reset_to_idle()
            logger.info("master key updated", extra={"event": "KEY_CHANGE"})
            print("Ka berhasil diubah. Sesi direset ke IDLE.")
        elif choice == "4":
            records = ring_buffer.records
            print("\n".join(records) if records else "(Belum ada log)")
        elif choice == "0":
            break


def main() -> None:
    parser = argparse.ArgumentParser(description="Alice Client")
    parser.add_argument("--config", default="config.alice.json")
    args = parser.parse_args()

    warning_capture = capture_config_warnings()
    try:
        config = load_config(args.config, "alice")
    except ConfigError as err:
        print(f"Konfigurasi error: {err}", file=sys.stderr)
        sys.exit(2)

    log_cfg = config.get("logging", {})
    logger = configure_logging("alice", log_cfg.get("file"), log_cfg.get("level", "INFO"))
    ring_buffer = RingBufferHandler()
    logger.addHandler(ring_buffer)
    flush_config_warnings(warning_capture, logger)

    ka = prompt_ka()
    session = AliceSession()
    try:
        run_interactive_menu(config, ka, session, logger, ring_buffer)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

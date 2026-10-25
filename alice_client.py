import argparse
import getpass
import logging
import socket
import sys
from typing import Any

from app_logging import RingBufferHandler, capture_config_warnings, configure_logging, flush_config_warnings
from config import ConfigError, load_config
from encoding_utils import validate_key
from network import NetworkError, close_socket, connect, recv_message, send_message
from protocol import (
    ProtocolError,
    build_bye,
    build_challenge_response,
    build_kdc_request,
    build_ticket,
    compute_kcv,
    new_nonce,
    open_challenge,
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


def authenticate_with_bob(
    config: dict[str, Any],
    session: AliceSession,
    logger: logging.Logger | None = None,
) -> socket.socket:
    if session.state != AliceState.KEY_READY or session.ticket is None or session.ks is None:
        raise StateError(f"cannot authenticate with bob from state: {session.state.value}")

    connect_timeout = float(config.get("timeouts", {}).get("connect", 5.0))
    step_timeout = float(config.get("timeouts", {}).get("step", 10.0))

    try:
        sock = connect(config["bob"]["host"], config["bob"]["port"], timeout=connect_timeout)
    except Exception:
        if logger is not None:
            logger.warning("failed to connect to bob", extra={"event": "BOB_CONNECT_FAIL"})
        raise

    try:
        send_message(sock, build_ticket(session.ticket))
        session.set_ticket_sent(sock)

        challenge = recv_message(sock, timeout=step_timeout)
        if challenge.get("type") == "AUTH_FAIL":
            raise ProtocolError(str(challenge.get("code", "BAD_FORMAT")), "bob rejected ticket")
        if challenge.get("type") == "ERROR":
            raise ProtocolError(str(challenge.get("code", "BAD_STATE")), "bob returned error")
        if challenge.get("type") != "CHALLENGE":
            raise ProtocolError("BAD_FORMAT", "expected CHALLENGE")

        n2 = open_challenge(session.ks, challenge)
        send_message(sock, build_challenge_response(session.ks, n2))

        auth_resp = recv_message(sock, timeout=step_timeout)
        if auth_resp.get("type") == "AUTH_FAIL":
            raise ProtocolError(str(auth_resp.get("code", "BAD_RESPONSE")), "authentication failed")
        if auth_resp.get("type") != "AUTH_OK":
            raise ProtocolError("BAD_FORMAT", "expected AUTH_OK")

        session.set_authenticated()
        if logger is not None:
            logger.info("authenticated with bob", extra={"event": "AUTH_OK"})
        return sock
    except Exception:
        session.reset_to_idle()
        close_socket(sock)
        if logger is not None:
            logger.warning("authentication with bob failed", extra={"event": "AUTH_FAIL"})
        raise


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
    menu = (
        "\n--- MENU ALICE ---\n"
        "[1] Minta Ks ke KDC (Langkah 1-2)\n"
        "[2] Autentikasi ke Bob (Langkah 3-5)\n"
        "[3] Status Sesi & KCV\n"
        "[4] Ubah Ka\n"
        "[5] Log Aktivitas\n"
        "[0] Keluar\n"
        "Pilih: "
    )

    while True:
        try:
            choice = input(menu).strip()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "1":
            try:
                ks, _ = request_session_key(config, ka, session, logger)
                print(f"Berhasil memperoleh Ks! State: {session.state.value} | KCV Ks: {compute_kcv(ks)}")
            except ProtocolError as err:
                print(f"Protokol error KDC: {err.code}")
            except Exception as err:
                print(f"Gagal memperoleh session key: {err}")
        elif choice == "2":
            try:
                authenticate_with_bob(config, session, logger)
                print(f"Berhasil terautentikasi dengan Bob! State: {session.state.value}")
            except ProtocolError as err:
                print(f"Autentikasi ditolak Bob: {err.code}")
            except Exception as err:
                print(f"Gagal autentikasi ke Bob: {err}")
        elif choice == "3":
            ks_kcv = compute_kcv(session.ks) if session.ks else "(belum ada)"
            print(f"State: {session.state.value} | KCV Ka: {compute_kcv(ka)} | KCV Ks: {ks_kcv}")
        elif choice == "4":
            new_ka = prompt_ka()
            ka = new_ka
            if session.client_sock:
                try:
                    send_message(session.client_sock, build_bye())
                except Exception:
                    pass
            session.reset_to_idle()
            logger.info("master key updated", extra={"event": "KEY_CHANGE"})
            print("Ka berhasil diubah. Sesi direset ke IDLE.")
        elif choice == "5":
            records = ring_buffer.records
            print("\n".join(records) if records else "(Belum ada log)")
        elif choice == "0":
            if session.client_sock:
                try:
                    send_message(session.client_sock, build_bye())
                except Exception:
                    pass
            session.reset_to_idle()
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
        session.reset_to_idle()


if __name__ == "__main__":
    main()

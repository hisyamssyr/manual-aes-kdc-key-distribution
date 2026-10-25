import argparse
import getpass
import logging
import socket
import sys
import threading
from typing import Any, Callable

from app_logging import RingBufferHandler, capture_config_warnings, configure_logging, flush_config_warnings
from config import ConfigError, load_config
from encoding_utils import validate_key
from network import NetworkError, close_socket, connect, recv_message, send_message
from protocol import (
    ProtocolError,
    build_challenge_response,
    build_kdc_request,
    build_ticket,
    compute_kcv,
    new_nonce,
    open_challenge,
    open_kdc_response,
)
from session import (
    AliceSession,
    AliceState,
    StateError,
    close_session,
    run_session_receiver,
    send_app_message,
)
import ui


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
    on_message: Callable[[dict[str, str]], None] | None = None,
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

        if on_message is not None:
            thread = threading.Thread(
                target=run_session_receiver,
                args=(session, config["peer_id"], on_message, lambda: None, logger),
                daemon=True,
            )
            session.receiver_thread = thread
            thread.start()

        return sock
    except Exception:
        session.reset_to_idle()
        close_socket(sock)
        if logger is not None:
            logger.warning("authentication with bob failed", extra={"event": "AUTH_FAIL"})
        raise


def close_alice_session(session: AliceSession, send_bye: bool = True) -> None:
    close_session(session, send_bye=send_bye)


def prompt_ka(exit_on_failure: bool = True) -> bytes | None:
    for _ in range(MAX_KEY_PROMPT_ATTEMPTS):
        try:
            first = getpass.getpass("Master Key Alice (Ka) (16 karakter ASCII): ")
            confirm = getpass.getpass("Konfirmasi Master Key Alice (Ka): ")
            if first != confirm:
                ui.print_error("Key tidak cocok, silakan coba lagi.")
                continue
            return validate_key(first)
        except ValueError as err:
            ui.print_error(f"Key tidak valid: {err}")
    if exit_on_failure:
        print("Gagal memasukkan key setelah 3 percobaan.", file=sys.stderr)
        sys.exit(2)
    ui.print_error("Gagal memasukkan key setelah 3 percobaan. Perubahan dibatalkan.")
    return None



def run_interactive_menu(
    config: dict[str, Any],
    initial_ka: bytes,
    session: AliceSession,
    logger: logging.Logger,
    ring_buffer: RingBufferHandler,
) -> None:
    ka = initial_ka
    menu = (
        "\n=== MENU ALICE ===\n"
        "1. Minta Session Key ke KDC (Langkah 1-2)\n"
        "2. Hubungi Bob dan Autentikasi (Langkah 3-5)\n"
        "3. Kirim Pesan Aplikasi\n"
        "4. Lihat Pesan Masuk\n"
        "5. Ubah Key Ka\n"
        "6. Lihat Status Sesi & KCV Ks\n"
        "7. Tutup Sesi (BYE)\n"
        "0. Keluar\n"
        "Pilih: "
    )

    while True:
        try:
            choice = ui.prompt_input(menu).strip()
        except (EOFError, KeyboardInterrupt):
            close_session(session, send_bye=True)
            break

        if choice == "1":
            try:
                ks, _ = request_session_key(config, ka, session, logger)
                ui.print_info(f"Berhasil memperoleh Ks. State: {session.state.value} | KCV Ks: {compute_kcv(ks)}")
            except ProtocolError as err:
                ui.print_error(f"Protokol error KDC: {err.code}")
            except Exception as err:
                ui.print_error(f"Gagal memperoleh session key: {err}")

        elif choice == "2":
            try:
                authenticate_with_bob(config, session, logger, ui.print_incoming)
                ui.print_info(f"Berhasil terautentikasi dengan Bob. State: {session.state.value}")
            except ProtocolError as err:
                ui.print_error(f"Autentikasi ditolak Bob: {err.code}")
            except Exception as err:
                ui.print_error(f"Gagal autentikasi ke Bob: {err}")

        elif choice == "3":
            if session.state != AliceState.AUTHENTICATED:
                ui.print_error("Sesi belum terautentikasi. Jalankan langkah 1 dan 2 terlebih dahulu.")
                continue
            text = ui.prompt_input("Masukkan plaintext pesan: ")
            try:
                plain, ct = send_app_message(session, config["id"], text, logger)
                ui.print_info(f"Pesan terkirim:\n  Plaintext : {plain}\n  Ciphertext: {ct}")
            except ValueError as err:
                ui.print_error(f"Pesan tidak valid: {err}")
            except Exception as err:
                ui.print_error(f"Gagal mengirim pesan: {err}")

        elif choice == "4":
            history = session.get_history()
            if not history:
                print("(Belum ada pesan)")
            else:
                print("\n=== RIWAYAT PESAN ===")
                for item in history:
                    print(f"[{item['from']}] {item['plaintext']}\n  Ciphertext: {item['ct']}")

        elif choice == "5":
            new_ka = prompt_ka(exit_on_failure=False)
            if new_ka is not None:
                close_session(session, send_bye=True)
                ka = new_ka
                logger.info("master key updated", extra={"event": "KEY_CHANGE"})
                ui.print_info("Ka berhasil diperbarui. Sesi direset ke IDLE.")

        elif choice == "6":
            kcv = compute_kcv(session.ks) if session.ks else "-"
            ui.render_status("alice", config["id"], config["peer_id"], session.state.value, kcv, session.unread_count)

        elif choice == "7":
            if session.state == AliceState.AUTHENTICATED:
                close_session(session, send_bye=True)
                ui.print_info("Sesi ditutup (BYE dikirim).")
            else:
                ui.print_error("Tidak ada sesi aktif untuk ditutup.")

        elif choice == "0":
            close_session(session, send_bye=True)
            break
        else:
            ui.print_error("Pilihan menu tidak valid.")



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
        close_session(session, send_bye=True)


if __name__ == "__main__":
    main()


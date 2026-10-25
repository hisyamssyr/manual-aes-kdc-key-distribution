import argparse
import getpass
import logging
import socket
import sys
import threading
import time
from typing import Any

from app_logging import RingBufferHandler, capture_config_warnings, configure_logging, flush_config_warnings
from config import ConfigError, load_config
from encoding_utils import validate_key
from network import (
    BadFrame,
    ConnectionClosed,
    FrameTooLarge,
    NetworkError,
    NetworkTimeout,
    close_socket,
    make_listener,
    recv_message,
    send_message,
)
from protocol import (
    ProtocolError,
    build_auth_fail,
    build_auth_ok,
    build_bye,
    build_challenge,
    build_error,
    check_challenge_response,
    compute_kcv,
    new_nonce,
    open_ticket,
)
from session import BobSession, BobState


MAX_KEY_PROMPT_ATTEMPTS = 3
SHUTDOWN_TIMEOUT_SECONDS = 2.0


class BobServer:
    def __init__(
        self: "BobServer",
        config: dict[str, Any],
        kb: bytes,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.kb = kb
        self.session = BobSession()
        self.lock = threading.RLock()
        self.listener: socket.socket | None = None
        self.running = False
        self.accept_thread: threading.Thread | None = None
        self.worker_thread: threading.Thread | None = None

        if logger is not None:
            self.logger = logger
            self.ring_buffer = next(
                (h for h in self.logger.handlers if isinstance(h, RingBufferHandler)), None
            )
        else:
            log_cfg = config.get("logging", {})
            self.logger = configure_logging("bob", log_cfg.get("file"), log_cfg.get("level", "INFO"))
            self.ring_buffer = RingBufferHandler()
            self.logger.addHandler(self.ring_buffer)

    def start(self: "BobServer") -> None:
        host = self.config["listen"]["host"]
        port = self.config["listen"]["port"]
        self.listener = make_listener(host, port)
        self.listener.settimeout(1.0)
        self.running = True
        self.logger.info("bob listener started", extra={"event": "LISTEN"})

        self.accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.accept_thread.start()

    def _accept_loop(self: "BobServer") -> None:
        while self.running and self.listener:
            try:
                sock, _ = self.listener.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break

            with self.lock:
                if self.session.state != BobState.LISTENING:
                    try:
                        send_message(sock, build_error("BUSY", "session active"))
                    except Exception:
                        pass
                    close_socket(sock)
                    continue

            self.worker_thread = threading.Thread(
                target=self._handle_client,
                args=(sock,),
                daemon=True,
            )
            self.worker_thread.start()

    def _handle_client(self: "BobServer", sock: socket.socket) -> None:
        step_timeout = float(self.config.get("timeouts", {}).get("step", 10.0))
        try:
            sock.settimeout(step_timeout)
            msg = recv_message(sock, timeout=step_timeout)
            if msg.get("type") != "TICKET":
                send_message(sock, build_error("BAD_STATE", "expected TICKET"))
                close_socket(sock)
                return

            ticket_data = msg.get("ticket")
            if not isinstance(ticket_data, dict):
                send_message(sock, build_auth_fail("BAD_FORMAT"))
                close_socket(sock)
                return

            with self.lock:
                current_kb = self.kb

            try:
                ks, id_a = open_ticket(ticket_data, current_kb, self.config["peer_id"])
            except ProtocolError as err:
                code = "BAD_FORMAT" if err.code == "BAD_FORMAT" else "DECRYPT_FAIL"
                send_message(sock, build_auth_fail(code))
                close_socket(sock)
                return
            except Exception:
                send_message(sock, build_auth_fail("DECRYPT_FAIL"))
                close_socket(sock)
                return

            n2 = new_nonce()
            with self.lock:
                self.session.set_ticket_received(ks, sock)
                self.session.set_challenge_sent(n2)

            send_message(sock, build_challenge(ks, n2))

            resp = recv_message(sock, timeout=step_timeout)
            if resp.get("type") != "CHALLENGE_RESP":
                send_message(sock, build_auth_fail("BAD_FORMAT"))
                self._reset_session()
                return

            if not check_challenge_response(ks, n2, resp):
                send_message(sock, build_auth_fail("BAD_RESPONSE"))
                self._reset_session()
                return

            send_message(sock, build_auth_ok())
            with self.lock:
                self.session.set_authenticated()
            self.logger.info("bob authenticated", extra={"event": "AUTH_OK", "peer": id_a})

        except NetworkTimeout:
            try:
                send_message(sock, build_auth_fail("TIMEOUT"))
            except Exception:
                pass
            self._reset_session()
        except (BadFrame, FrameTooLarge, ConnectionClosed, NetworkError):
            self._reset_session()
        except Exception:
            self._reset_session()

    def _reset_session(self: "BobServer") -> None:
        with self.lock:
            self.session.reset_to_listening()

    def change_key(self: "BobServer", new_kb: bytes) -> None:
        valid_key = validate_key(new_kb.decode("ascii"))
        with self.lock:
            if self.session.client_sock:
                try:
                    send_message(self.session.client_sock, build_bye())
                except Exception:
                    pass
            self.session.reset_to_listening()
            self.kb = valid_key
        self.logger.info("kb updated", extra={"event": "KEY_CHANGE"})

    def stop(self: "BobServer") -> None:
        self.running = False
        if self.listener is not None:
            close_socket(self.listener)
            self.listener = None

        with self.lock:
            if self.session.client_sock:
                try:
                    send_message(self.session.client_sock, build_bye())
                except Exception:
                    pass
            self.session.reset_to_listening()

        if self.accept_thread and self.accept_thread.is_alive():
            self.accept_thread.join(timeout=SHUTDOWN_TIMEOUT_SECONDS)
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=SHUTDOWN_TIMEOUT_SECONDS)

        self.logger.info("bob server stopped", extra={"event": "SHUTDOWN"})


def prompt_kb() -> bytes:
    for _ in range(MAX_KEY_PROMPT_ATTEMPTS):
        try:
            first = getpass.getpass("Master Key Bob (Kb) (16 karakter ASCII): ")
            confirm = getpass.getpass("Konfirmasi Master Key Bob (Kb): ")
            if first != confirm:
                print("Key tidak cocok, silakan coba lagi.", file=sys.stderr)
                continue
            return validate_key(first)
        except ValueError as err:
            print(f"Key tidak valid: {err}", file=sys.stderr)
    print("Gagal memasukkan key setelah 3 percobaan.", file=sys.stderr)
    sys.exit(2)


def run_interactive_menu(server: BobServer) -> None:
    menu = "\n--- MENU BOB ---\n[1] Status Sesi & KCV\n[2] Ubah Kb\n[3] Log Aktivitas\n[0] Keluar\nPilih: "
    while server.running:
        try:
            choice = input(menu).strip()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "1":
            with server.lock:
                st = server.session.state.value
                ks_kcv = compute_kcv(server.session.ks) if server.session.ks else "(belum ada)"
                kb_kcv = compute_kcv(server.kb)
            print(f"\nState Sesi: {st} | KCV Kb: {kb_kcv} | KCV Ks: {ks_kcv}")
        elif choice == "2":
            new_kb = prompt_kb()
            server.change_key(new_kb)
            print("Kb berhasil diperbarui. Sesi aktif diputus.")
        elif choice == "3":
            records = server.ring_buffer.records if server.ring_buffer else []
            print("\n".join(records) if records else "(Belum ada log)")
        elif choice == "0":
            break

    server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Bob Client/Server")
    parser.add_argument("--config", default="config.bob.json")
    args = parser.parse_args()

    warning_capture = capture_config_warnings()
    try:
        config = load_config(args.config, "bob")
    except ConfigError as err:
        print(f"Konfigurasi error: {err}", file=sys.stderr)
        sys.exit(2)

    log_cfg = config.get("logging", {})
    logger = configure_logging("bob", log_cfg.get("file"), log_cfg.get("level", "INFO"))
    ring_buffer = RingBufferHandler()
    logger.addHandler(ring_buffer)
    flush_config_warnings(warning_capture, logger)

    kb = prompt_kb()
    server = BobServer(config, kb, logger)
    server.start()

    try:
        run_interactive_menu(server)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()

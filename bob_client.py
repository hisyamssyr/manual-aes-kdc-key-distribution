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
    build_challenge,
    build_error,
    check_challenge_response,
    compute_kcv,
    new_nonce,
    open_ticket,
)
from session import BobSession, BobState, close_session, run_session_receiver, send_app_message
import ui


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

            try:
                if not check_challenge_response(ks, n2, resp):
                    send_message(sock, build_auth_fail("BAD_RESPONSE"))
                    self._reset_session()
                    return
            except Exception:
                send_message(sock, build_auth_fail("BAD_FORMAT"))
                self._reset_session()
                return

            send_message(sock, build_auth_ok())
            with self.lock:
                self.session.set_authenticated()
            self.logger.info("bob authenticated", extra={"event": "AUTH_OK", "peer": id_a})

            run_session_receiver(
                self.session,
                self.config["peer_id"],
                ui.print_incoming,
                self._reset_session,
                self.logger,
            )

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
        self.close_active_session()
        with self.lock:
            self.kb = valid_key
        self.logger.info("kb updated", extra={"event": "KEY_CHANGE"})

    def close_active_session(self: "BobServer") -> None:
        close_session(self.session, send_bye=True)

    def stop(self: "BobServer") -> None:
        self.running = False
        if self.listener is not None:
            close_socket(self.listener)
            self.listener = None

        close_session(self.session, send_bye=True)

        if self.accept_thread and self.accept_thread.is_alive():
            self.accept_thread.join(timeout=SHUTDOWN_TIMEOUT_SECONDS)
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=SHUTDOWN_TIMEOUT_SECONDS)

        self.logger.info("bob server stopped", extra={"event": "SHUTDOWN"})


def prompt_kb(exit_on_failure: bool = True) -> bytes | None:
    for _ in range(MAX_KEY_PROMPT_ATTEMPTS):
        try:
            first = getpass.getpass("Master Key Bob (Kb) (16 karakter ASCII): ")
            confirm = getpass.getpass("Konfirmasi Master Key Bob (Kb): ")
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



def run_interactive_menu(server: BobServer) -> None:
    menu = (
        "\n=== MENU BOB ===\n"
        "1. Lihat Status Sesi & KCV Ks\n"
        "2. Kirim Pesan Aplikasi\n"
        "3. Lihat Pesan Masuk\n"
        "4. Ubah Key Kb\n"
        "5. Tutup Sesi (BYE)\n"
        "0. Keluar\n"
        "Pilih: "
    )
    while server.running:
        try:
            choice = ui.prompt_input(menu).strip()
        except (EOFError, KeyboardInterrupt):
            server.close_active_session()
            break

        if choice == "1":
            kcv = compute_kcv(server.session.ks) if server.session.ks else "-"
            ui.render_status("bob", server.config["id"], server.config["peer_id"], server.session.state.value, kcv, server.session.unread_count)

        elif choice == "2":
            if server.session.state != BobState.AUTHENTICATED:
                ui.print_error("Sesi belum terautentikasi. Tunggu koneksi dari Alice.")
                continue
            text = ui.prompt_input("Masukkan plaintext pesan: ")
            try:
                plain, ct = send_app_message(server.session, server.config["id"], text, server.logger)
                ui.print_info(f"Pesan terkirim:\n  Plaintext : {plain}\n  Ciphertext: {ct}")
            except ValueError as err:
                ui.print_error(f"Pesan tidak valid: {err}")
            except Exception as err:
                ui.print_error(f"Gagal mengirim pesan: {err}")

        elif choice == "3":
            history = server.session.get_history()
            if not history:
                print("(Belum ada pesan)")
            else:
                print("\n=== RIWAYAT PESAN ===")
                for item in history:
                    print(f"[{item['from']}] {item['plaintext']}\n  Ciphertext: {item['ct']}")

        elif choice == "4":
            new_kb = prompt_kb(exit_on_failure=False)
            if new_kb is not None:
                server.change_key(new_kb)
                ui.print_info("Kb berhasil diperbarui. Sesi aktif diputus.")

        elif choice == "5":
            if server.session.state == BobState.AUTHENTICATED:
                server.close_active_session()
                ui.print_info("Sesi ditutup (BYE dikirim).")
            else:
                ui.print_error("Tidak ada sesi aktif untuk ditutup.")

        elif choice == "0":
            server.close_active_session()
            break
        else:
            ui.print_error("Pilihan menu tidak valid.")

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


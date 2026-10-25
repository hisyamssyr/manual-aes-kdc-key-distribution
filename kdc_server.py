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
from encoding_utils import validate_id, validate_key
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
    build_kdc_error,
    build_kdc_response,
    new_session_key,
    parse_kdc_request,
)


MAX_CONCURRENT_CONNECTIONS = 32
MAX_KEY_PROMPT_ATTEMPTS = 3
SHUTDOWN_JOIN_TIMEOUT_SECONDS = 2.0


class KDCServer:
    def __init__(
        self: "KDCServer",
        config: dict[str, Any],
        initial_keys: dict[str, bytes] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.lock = threading.RLock()
        self.registry: dict[str, bytes] = dict(initial_keys) if initial_keys else {}
        self.listener: socket.socket | None = None
        self.semaphore = threading.Semaphore(MAX_CONCURRENT_CONNECTIONS)
        self.active_sockets: set[socket.socket] = set()
        self.running = False
        self.start_time: float = 0.0
        self.accept_thread: threading.Thread | None = None
        self.client_threads: list[threading.Thread] = []

        self.total_requests = 0
        self.success_requests = 0
        self.error_counts: dict[str, int] = {}

        if logger is not None:
            self.logger = logger
            self.ring_buffer = next(
                (h for h in self.logger.handlers if isinstance(h, RingBufferHandler)), None
            )
        else:
            log_cfg = config.get("logging", {})
            self.logger = configure_logging("kdc", log_cfg.get("file"), log_cfg.get("level", "INFO"))
            self.ring_buffer = RingBufferHandler()
            self.logger.addHandler(self.ring_buffer)

    def provision_keys_interactively(self: "KDCServer") -> None:
        for identity in self.config.get("registry_ids", []):
            key = prompt_key_for_id(identity)
            with self.lock:
                self.registry[identity] = key

    def start(self: "KDCServer") -> None:
        self.listener = make_listener(self.config["listen"]["host"], self.config["listen"]["port"])
        self.listener.settimeout(1.0)
        self.running = True
        self.start_time = time.time()
        self.logger.info("kdc listener started", extra={"event": "LISTEN"})

        self.accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.accept_thread.start()

    def _accept_loop(self: "KDCServer") -> None:
        while self.running and self.listener:
            try:
                sock, addr = self.listener.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break

            if not self.semaphore.acquire(blocking=False):
                close_socket(sock)
                continue

            with self.lock:
                self.active_sockets.add(sock)

            t = threading.Thread(
                target=self._handle_client,
                args=(sock, addr),
                daemon=True,
            )
            with self.lock:
                self.client_threads.append(t)
            t.start()

    def _handle_client(
        self: "KDCServer", client_sock: socket.socket, _addr: tuple[str, int]
    ) -> None:
        step_timeout = float(self.config.get("timeouts", {}).get("step", 10.0))
        try:
            req = recv_message(client_sock, timeout=step_timeout)
            with self.lock:
                self.total_requests += 1

            try:
                id_a, id_b, n1 = parse_kdc_request(req)
            except ProtocolError as err:
                self._record_error(err.code)
                send_message(client_sock, build_kdc_error(err.code, "malformed request"))
                return
            except Exception:
                self._record_error("BAD_FORMAT")
                send_message(client_sock, build_kdc_error("BAD_FORMAT", "malformed request"))
                return

            with self.lock:
                ka, kb = self.registry.get(id_a), self.registry.get(id_b)

            if ka is None or kb is None:
                self._record_error("UNKNOWN_ID")
                send_message(client_sock, build_kdc_error("UNKNOWN_ID", "unregistered id"))
                return

            try:
                ks = new_session_key()
                resp = build_kdc_response(ka, kb, ks, id_a, id_b, n1)
                send_message(client_sock, resp)
                with self.lock:
                    self.success_requests += 1
                self.logger.info("session key issued", extra={"event": "KDC_RESP", "id_a": id_a, "id_b": id_b})
            except Exception:
                self._record_error("INTERNAL")
                send_message(client_sock, build_kdc_error("INTERNAL", "internal error"))

        except (BadFrame, FrameTooLarge, ConnectionClosed, NetworkTimeout, NetworkError):
            self._record_error("NETWORK_ERROR")
        except Exception:
            self._record_error("INTERNAL")
            try:
                send_message(client_sock, build_kdc_error("INTERNAL", "internal error"))
            except Exception:
                pass
        finally:
            with self.lock:
                self.active_sockets.discard(client_sock)
            close_socket(client_sock)
            self.semaphore.release()

    def _record_error(self: "KDCServer", error_code: str) -> None:
        with self.lock:
            self.error_counts[error_code] = self.error_counts.get(error_code, 0) + 1
        self.logger.warning("request failed", extra={"event": "KDC_ERR", "code": error_code})

    def change_key(self: "KDCServer", identity: str, new_key: bytes) -> None:
        valid_id = validate_id(identity)
        valid_key = validate_key(new_key.decode("ascii"))
        with self.lock:
            self.registry[valid_id] = valid_key
        self.logger.info("key updated", extra={"event": "KEY_CHANGE", "id": valid_id})

    def get_status(self: "KDCServer") -> dict[str, Any]:
        with self.lock:
            return {
                "uptime": time.time() - self.start_time if self.running else 0.0,
                "registered_ids": sorted(list(self.registry.keys())),
                "active_connections": len(self.active_sockets),
                "total_requests": self.total_requests,
                "success_requests": self.success_requests,
                "error_counts": dict(self.error_counts),
            }

    def stop(self: "KDCServer") -> None:
        self.running = False
        if self.listener is not None:
            close_socket(self.listener)
            self.listener = None

        with self.lock:
            for sock in list(self.active_sockets):
                close_socket(sock)
            self.active_sockets.clear()
            self.registry.clear()

        if self.accept_thread and self.accept_thread.is_alive():
            self.accept_thread.join(timeout=SHUTDOWN_JOIN_TIMEOUT_SECONDS)

        with self.lock:
            for thread in self.client_threads:
                if thread.is_alive():
                    thread.join(timeout=SHUTDOWN_JOIN_TIMEOUT_SECONDS)
            self.client_threads.clear()

        self.logger.info("kdc server stopped", extra={"event": "SHUTDOWN"})


def prompt_key_for_id(identity: str, exit_on_failure: bool = True) -> bytes | None:
    for _ in range(MAX_KEY_PROMPT_ATTEMPTS):
        try:
            first = getpass.getpass(f"Key [{identity}] (16 karakter ASCII): ")
            confirm = getpass.getpass(f"Konfirmasi [{identity}]: ")
            if first != confirm:
                print("Key tidak cocok, silakan coba lagi.", file=sys.stderr)
                continue
            return validate_key(first)
        except ValueError as err:
            print(f"Key tidak valid: {err}", file=sys.stderr)
    if exit_on_failure:
        print("Gagal memasukkan key setelah 3 percobaan.", file=sys.stderr)
        sys.exit(2)
    print("Gagal memasukkan key setelah 3 percobaan. Perubahan dibatalkan.", file=sys.stderr)
    return None



def run_interactive_menu(server: KDCServer) -> None:
    menu = "\n--- MENU KDC ---\n[1] Status\n[2] Ubah Key\n[3] Log Aktivitas\n[0] Keluar\nPilih: "
    while server.running:
        try:
            choice = input(menu).strip()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "1":
            st = server.get_status()
            print(f"\nUptime: {st['uptime']:.1f}s | Terdaftar: {st['registered_ids']} | Aktif: {st['active_connections']}")
            print(f"Request Total: {st['total_requests']} | Sukses: {st['success_requests']} | Error: {st['error_counts']}")
        elif choice == "2":
            target = input("Masukkan ID target: ").strip()
            with server.lock:
                if target not in server.registry:
                    print(f"ID '{target}' tidak ditemukan di registry.")
                    continue
            new_key = prompt_key_for_id(target, exit_on_failure=False)
            if new_key is not None:
                server.change_key(target, new_key)
                print(f"Key untuk '{target}' berhasil diubah.")

        elif choice == "3":
            records = server.ring_buffer.records if server.ring_buffer else []
            print("\n".join(records) if records else "(Belum ada log)")
        elif choice == "0":
            break

    server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="KDC Server")
    parser.add_argument("--config", default="config.kdc.json")
    args = parser.parse_args()

    warning_capture = capture_config_warnings()
    try:
        config = load_config(args.config, "kdc")
    except ConfigError as err:
        print(f"Konfigurasi error: {err}", file=sys.stderr)
        sys.exit(2)

    server = KDCServer(config)
    flush_config_warnings(warning_capture, server.logger)
    server.provision_keys_interactively()
    server.start()

    try:
        run_interactive_menu(server)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()

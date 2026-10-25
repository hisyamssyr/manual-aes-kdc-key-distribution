from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import logging
import socket
import threading
from typing import Any, Callable

from app_logging import audit_app_message
from encoding_utils import validate_plaintext
from network import (
    BadFrame,
    ConnectionClosed,
    FrameTooLarge,
    NetworkError,
    NetworkTimeout,
    close_socket,
    recv_message,
    send_message,
)
from protocol import (
    ProtocolError,
    build_app_msg,
    build_bye,
    build_error,
    open_app_msg,
)


MAX_HISTORY_ENTRIES = 100


class AliceState(str, Enum):
    IDLE = "IDLE"
    REQUESTED = "REQUESTED"
    KEY_READY = "KEY_READY"
    TICKET_SENT = "TICKET_SENT"
    AUTHENTICATED = "AUTHENTICATED"
    CLOSED = "CLOSED"


class BobState(str, Enum):
    LISTENING = "LISTENING"
    TICKET_RECEIVED = "TICKET_RECEIVED"
    CHALLENGE_SENT = "CHALLENGE_SENT"
    AUTHENTICATED = "AUTHENTICATED"
    CLOSED = "CLOSED"


class StateError(Exception):
    pass


BOB_ALLOWED_TRANSITIONS: dict[BobState, set[BobState]] = {
    BobState.LISTENING: {BobState.TICKET_RECEIVED, BobState.CLOSED},
    BobState.TICKET_RECEIVED: {BobState.CHALLENGE_SENT, BobState.LISTENING, BobState.CLOSED},
    BobState.CHALLENGE_SENT: {BobState.AUTHENTICATED, BobState.LISTENING, BobState.CLOSED},
    BobState.AUTHENTICATED: {BobState.LISTENING, BobState.CLOSED},
    BobState.CLOSED: {BobState.LISTENING},
}


def assert_bob_transition(current: BobState, target: BobState) -> None:
    if target not in BOB_ALLOWED_TRANSITIONS.get(current, set()):
        raise StateError(f"illegal transition: {current.value} -> {target.value}")


@dataclass
class AliceSession:
    state: AliceState = AliceState.IDLE
    ks: bytes | None = None
    ticket: dict[str, Any] | None = None
    last_n1: bytes | None = None
    client_sock: socket.socket | None = None
    send_lock: threading.Lock = field(default_factory=threading.Lock)
    close_event: threading.Event = field(default_factory=threading.Event)
    message_history: list[dict[str, str]] = field(default_factory=list)
    unread_count: int = 0
    receiver_thread: threading.Thread | None = None

    def begin_request(self: "AliceSession", n1: bytes) -> None:
        if self.state not in (AliceState.IDLE, AliceState.KEY_READY):
            raise StateError(f"cannot request session key from state: {self.state.value}")
        self.state = AliceState.REQUESTED
        self.ks, self.ticket = None, None
        self.last_n1 = n1

    def finish_request_success(
        self: "AliceSession", ks: bytes, ticket: dict[str, Any]
    ) -> None:
        self.state = AliceState.KEY_READY
        self.ks, self.ticket, self.last_n1 = ks, ticket, None

    def set_ticket_sent(self: "AliceSession", sock: socket.socket) -> None:
        if self.state != AliceState.KEY_READY:
            raise StateError(f"cannot send ticket from state: {self.state.value}")
        self.state = AliceState.TICKET_SENT
        self.client_sock = sock

    def set_authenticated(self: "AliceSession") -> None:
        if self.state != AliceState.TICKET_SENT:
            raise StateError(f"cannot authenticate from state: {self.state.value}")
        self.state = AliceState.AUTHENTICATED
        self.close_event.clear()

    def record_message(
        self: "AliceSession", from_id: str, plaintext: str, ct_hex: str, incoming: bool = True
    ) -> dict[str, str]:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "from": from_id,
            "plaintext": plaintext,
            "ct": ct_hex,
        }
        self.message_history.append(entry)
        if len(self.message_history) > MAX_HISTORY_ENTRIES:
            self.message_history.pop(0)
        if incoming:
            self.unread_count += 1
        return entry

    def get_history(self: "AliceSession") -> list[dict[str, str]]:
        self.unread_count = 0
        return list(self.message_history)

    def reset_to_idle(self: "AliceSession") -> None:
        self.state = AliceState.IDLE
        self.ks, self.ticket, self.last_n1 = None, None, None
        self.close_event.set()
        if self.client_sock is not None:
            close_socket(self.client_sock)
            self.client_sock = None


@dataclass
class BobSession:
    state: BobState = BobState.LISTENING
    ks: bytes | None = None
    n2: bytes | None = None
    client_sock: socket.socket | None = None
    send_lock: threading.Lock = field(default_factory=threading.Lock)
    close_event: threading.Event = field(default_factory=threading.Event)
    message_history: list[dict[str, str]] = field(default_factory=list)
    unread_count: int = 0
    receiver_thread: threading.Thread | None = None

    def set_ticket_received(self: "BobSession", ks: bytes, sock: socket.socket) -> None:
        assert_bob_transition(self.state, BobState.TICKET_RECEIVED)
        self.state = BobState.TICKET_RECEIVED
        self.ks = ks
        self.client_sock = sock

    def set_challenge_sent(self: "BobSession", n2: bytes) -> None:
        assert_bob_transition(self.state, BobState.CHALLENGE_SENT)
        self.state = BobState.CHALLENGE_SENT
        self.n2 = n2

    def set_authenticated(self: "BobSession") -> None:
        assert_bob_transition(self.state, BobState.AUTHENTICATED)
        self.state = BobState.AUTHENTICATED
        self.close_event.clear()

    def record_message(
        self: "BobSession", from_id: str, plaintext: str, ct_hex: str, incoming: bool = True
    ) -> dict[str, str]:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "from": from_id,
            "plaintext": plaintext,
            "ct": ct_hex,
        }
        self.message_history.append(entry)
        if len(self.message_history) > MAX_HISTORY_ENTRIES:
            self.message_history.pop(0)
        if incoming:
            self.unread_count += 1
        return entry

    def get_history(self: "BobSession") -> list[dict[str, str]]:
        self.unread_count = 0
        return list(self.message_history)

    def reset_to_listening(self: "BobSession") -> None:
        self.state = BobState.LISTENING
        self.ks = None
        self.n2 = None
        self.close_event.set()
        if self.client_sock is not None:
            close_socket(self.client_sock)
            self.client_sock = None


def send_app_message(
    session: AliceSession | BobSession,
    sender_id: str,
    plaintext: str,
    logger: logging.Logger | None = None,
) -> tuple[str, str]:
    if session.state not in (AliceState.AUTHENTICATED, BobState.AUTHENTICATED):
        raise StateError("sesi belum terautentikasi")
    if session.ks is None or session.client_sock is None:
        raise StateError("kunci sesi atau koneksi tidak tersedia")

    validate_plaintext(plaintext)
    msg = build_app_msg(sender_id, session.ks, plaintext)

    with session.send_lock:
        send_message(session.client_sock, msg)

    ct_hex = str(msg["body"]["ct"]).lower()
    session.record_message(sender_id, plaintext, ct_hex, incoming=False)

    if logger is not None:
        audit_app_message(logger, "OUT", sender_id, plaintext, ct_hex)
    return plaintext, ct_hex


def run_session_receiver(
    session: AliceSession | BobSession,
    peer_id: str,
    on_message: Callable[[dict[str, str]], None],
    on_close: Callable[[], None],
    logger: logging.Logger | None = None,
) -> None:
    sock = session.client_sock
    ks = session.ks
    if sock is None or ks is None:
        return

    while not session.close_event.is_set():
        try:
            msg = recv_message(sock, timeout=None)
            msg_type = msg.get("type")

            if msg_type == "APP_MSG":
                try:
                    from_id, plaintext = open_app_msg(msg, ks, expected_from=peer_id)
                    ct_hex = str(msg.get("body", {}).get("ct", "")).lower()
                    entry = session.record_message(from_id, plaintext, ct_hex, incoming=True)
                    if logger is not None:
                        audit_app_message(logger, "IN", from_id, plaintext, ct_hex)
                    on_message(entry)
                except ProtocolError as err:
                    code = "DECRYPT_FAIL" if err.code == "DECRYPT_FAIL" else "BAD_FORMAT"
                    with session.send_lock:
                        try:
                            send_message(sock, build_error(code, "pesan aplikasi gagal diproses"))
                        except Exception:
                            pass
                except Exception:
                    with session.send_lock:
                        try:
                            send_message(sock, build_error("DECRYPT_FAIL", "dekripsi gagal"))
                        except Exception:
                            pass

            elif msg_type == "BYE":
                session.close_event.set()
                with session.send_lock:
                    try:
                        send_message(sock, build_bye())
                    except Exception:
                        pass
                on_close()
                break

            elif msg_type == "ERROR":
                pass

            else:
                with session.send_lock:
                    try:
                        send_message(sock, build_error("BAD_STATE", "tipe pesan tidak valid"))
                    except Exception:
                        pass
                session.close_event.set()
                on_close()
                break

        except (BadFrame, FrameTooLarge, ConnectionClosed, NetworkError):
            session.close_event.set()
            on_close()
            break
        except Exception:
            session.close_event.set()
            on_close()
            break

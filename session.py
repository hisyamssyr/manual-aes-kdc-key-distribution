from dataclasses import dataclass
from enum import Enum
import socket
from typing import Any


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

    def reset_to_idle(self: "AliceSession") -> None:
        self.state = AliceState.IDLE
        self.ks, self.ticket, self.last_n1 = None, None, None
        if self.client_sock is not None:
            try:
                self.client_sock.close()
            except OSError:
                pass
            self.client_sock = None


@dataclass
class BobSession:
    state: BobState = BobState.LISTENING
    ks: bytes | None = None
    n2: bytes | None = None
    client_sock: socket.socket | None = None

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

    def reset_to_listening(self: "BobSession") -> None:
        self.state = BobState.LISTENING
        self.ks = None
        self.n2 = None
        if self.client_sock is not None:
            try:
                self.client_sock.close()
            except OSError:
                pass
            self.client_sock = None

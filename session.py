from dataclasses import dataclass
from enum import Enum
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


@dataclass
class AliceSession:
    state: AliceState = AliceState.IDLE
    ks: bytes | None = None
    ticket: dict[str, Any] | None = None
    last_n1: bytes | None = None

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

    def reset_to_idle(self: "AliceSession") -> None:
        self.state = AliceState.IDLE
        self.ks, self.ticket, self.last_n1 = None, None, None

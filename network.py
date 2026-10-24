import errno
import json
import math
import socket
import struct
import time
from typing import Any


BACKLOG = 16
HEADER_SIZE = 4
MAX_PAYLOAD_SIZE = 65_536


class NetworkError(Exception):
    pass


class ConnectionClosed(NetworkError):
    pass


class FrameTooLarge(NetworkError):
    pass


class BadFrame(NetworkError):
    pass


class BadHeader(BadFrame):
    pass


class BadPayload(BadFrame):
    pass


class NetworkTimeout(NetworkError):
    pass


def make_listener(host: str, port: int) -> socket.socket:
    listener: socket.socket | None = None
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(BACKLOG)
        return listener
    except OSError as error:
        if listener is not None:
            close_socket(listener)
        raise NetworkError(f"tidak dapat listen pada {host}:{port}") from error


def connect(host: str, port: int, timeout: float) -> socket.socket:
    connection_timeout = _validate_timeout(timeout, "timeout koneksi")
    connection: socket.socket | None = None
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(connection_timeout)
        connection.connect((host, port))
        return connection
    except OSError as error:
        if connection is not None:
            close_socket(connection)
        raise NetworkError(f"tidak dapat terhubung ke {host}:{port}") from error


def send_message(sock: socket.socket, obj: dict[str, Any]) -> None:
    if not isinstance(obj, dict):
        raise ValueError("pesan harus berupa dict")
    try:
        payload = json.dumps(
            obj, allow_nan=False, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    except (OverflowError, TypeError, ValueError) as error:
        raise ValueError("pesan tidak dapat diserialisasi sebagai JSON") from error
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise FrameTooLarge("payload melebihi batas 65536 byte")

    try:
        sock.sendall(struct.pack("!I", len(payload)) + payload)
    except socket.timeout as error:
        raise NetworkTimeout("waktu pengiriman pesan habis") from error
    except (BrokenPipeError, ConnectionResetError) as error:
        raise ConnectionClosed("koneksi ditutup saat mengirim") from error
    except OSError as error:
        if error.errno in {errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN}:
            raise ConnectionClosed("koneksi ditutup saat mengirim") from error
        raise NetworkError("gagal mengirim pesan") from error


def recv_message(sock: socket.socket, timeout: float | None = None) -> dict[str, Any]:
    receive_timeout = (
        None if timeout is None else _validate_timeout(timeout, "timeout penerimaan")
    )

    previous_timeout = sock.gettimeout()
    if receive_timeout is None:
        sock.settimeout(None)
    deadline = (
        time.monotonic() + receive_timeout if receive_timeout is not None else None
    )
    try:
        header = _recv_exact(sock, HEADER_SIZE, deadline)
        payload_size = struct.unpack("!I", header)[0]
        if payload_size == 0:
            raise BadHeader("header frame bernilai nol")
        if payload_size > MAX_PAYLOAD_SIZE:
            raise FrameTooLarge("payload melebihi batas 65536 byte")
        payload = _recv_exact(sock, payload_size, deadline)
        return _decode_payload(payload)
    finally:
        try:
            sock.settimeout(previous_timeout)
        except OSError:
            pass


def close_socket(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _recv_exact(sock: socket.socket, size: int, deadline: float | None) -> bytes:
    received = bytearray()
    while len(received) < size:
        _apply_receive_timeout(sock, deadline)
        try:
            chunk = sock.recv(size - len(received))
        except socket.timeout as error:
            raise NetworkTimeout("waktu penerimaan frame habis") from error
        except (ConnectionResetError, BrokenPipeError) as error:
            raise ConnectionClosed("koneksi ditutup saat menerima") from error
        except OSError as error:
            if error.errno in {errno.ECONNRESET, errno.ENOTCONN}:
                raise ConnectionClosed("koneksi ditutup saat menerima") from error
            raise NetworkError("gagal menerima pesan") from error
        if not chunk:
            raise ConnectionClosed("koneksi ditutup saat menerima")
        received.extend(chunk)
    return bytes(received)


def _validate_timeout(timeout: Any, label: str) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError(f"{label} harus lebih besar dari nol")
    try:
        value = float(timeout)
    except (OverflowError, ValueError) as error:
        raise ValueError(f"{label} harus lebih besar dari nol") from error
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{label} harus lebih besar dari nol")
    return value


def _apply_receive_timeout(sock: socket.socket, deadline: float | None) -> None:
    if deadline is None:
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise NetworkTimeout("waktu penerimaan frame habis")
    sock.settimeout(remaining)


def _decode_payload(payload: bytes) -> dict[str, Any]:
    try:
        decoded = payload.decode("utf-8")
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise BadPayload("payload JSON tidak valid") from error
    if not isinstance(parsed, dict):
        raise BadPayload("payload JSON harus berupa objek")
    return parsed


def _reject_duplicate_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"JSON constant is not allowed: {value}")

import secrets
from typing import Any

from encoding_utils import hex_to_bytes, validate_id, validate_key, validate_plaintext
from manual_aes import AESError, BLOCK_SIZE, decrypt_cbc, encrypt_block, encrypt_cbc, generate_iv


AUTH_FAIL_CODES = frozenset({"DECRYPT_FAIL", "BAD_RESPONSE", "BAD_FORMAT", "TIMEOUT"})
ENVELOPE_FIELDS = frozenset({"iv", "ct"})
ERROR_CODES = frozenset({"BAD_STATE", "BUSY", "DECRYPT_FAIL", "BAD_FORMAT", "TIMEOUT", "INTERNAL"})
KDC_ERROR_CODES = frozenset({"UNKNOWN_ID", "BAD_FORMAT", "INTERNAL"})
MAX_NONCE = (1 << 64) - 1
NONCE_SIZE = 8
PROTOCOL_VERSION = 1
SESSION_KEY_ALPHABET = "".join(chr(value) for value in range(0x21, 0x7F))
MESSAGE_FIELDS = {
    "KDC_REQ": frozenset({"v", "type", "id_a", "id_b", "n1"}),
    "KDC_RESP": frozenset({"v", "type", "for_a", "ticket"}),
    "KDC_ERR": frozenset({"v", "type", "code", "msg"}),
    "TICKET": frozenset({"v", "type", "ticket"}),
    "CHALLENGE": frozenset({"v", "type", "body"}),
    "CHALLENGE_RESP": frozenset({"v", "type", "body"}),
    "AUTH_OK": frozenset({"v", "type"}),
    "AUTH_FAIL": frozenset({"v", "type", "code"}),
    "APP_MSG": frozenset({"v", "type", "from", "body"}),
    "BYE": frozenset({"v", "type"}),
    "ERROR": frozenset({"v", "type", "code", "msg"}),
}


class ProtocolError(Exception):
    def __init__(self: "ProtocolError", code: str, msg: str = "") -> None:
        self.code = code
        super().__init__(msg or code)


def new_session_key() -> bytes:
    return "".join(secrets.choice(SESSION_KEY_ALPHABET) for _ in range(BLOCK_SIZE)).encode("ascii")


def new_nonce() -> bytes:
    return secrets.token_bytes(NONCE_SIZE)


def f(n2: int) -> int:
    if isinstance(n2, bool) or not isinstance(n2, int) or not 0 <= n2 <= MAX_NONCE:
        raise ValueError("nonce must be an unsigned 64-bit integer")
    return (n2 - 1) % (MAX_NONCE + 1)


def seal(key: bytes, plaintext: bytes, *, iv: bytes | None = None) -> dict[str, str]:
    _validate_cipher_key(key)
    _require_bytes(plaintext)
    selected_iv = generate_iv() if iv is None else iv
    _validate_iv(selected_iv)
    try:
        ciphertext = encrypt_cbc(key, selected_iv, plaintext)
    except (AESError, TypeError) as error:
        raise ProtocolError("BAD_FORMAT") from error
    return {"iv": selected_iv.hex(), "ct": ciphertext.hex()}


def unseal(key: bytes, envelope: dict[str, Any]) -> bytes:
    _validate_cipher_key(key)
    iv, ciphertext, _ = _parse_envelope(envelope)
    try:
        return decrypt_cbc(key, iv, ciphertext)
    except AESError as error:
        raise ProtocolError("DECRYPT_FAIL") from error
    except TypeError as error:
        raise ProtocolError("BAD_FORMAT") from error


def encode_r_a(ks: bytes, id_a: str, id_b: str, n1: bytes) -> bytes:
    validated_ks = _validate_session_key(ks)
    encoded_id_a = _encode_id(id_a)
    encoded_id_b = _encode_id(id_b)
    validated_n1 = _validate_nonce(n1)
    return validated_ks + encoded_id_a + encoded_id_b + validated_n1


def decode_r_a(data: bytes) -> tuple[bytes, str, str, bytes]:
    raw_data = _validate_serialized_data(data)
    if len(raw_data) < BLOCK_SIZE + 1 + 1 + NONCE_SIZE:
        raise ProtocolError("BAD_FORMAT")

    ks = _validate_session_key(raw_data[:BLOCK_SIZE])
    id_a, after_id_a = _decode_id(raw_data, BLOCK_SIZE)
    id_b, after_id_b = _decode_id(raw_data, after_id_a)
    n1 = raw_data[after_id_b:]
    _validate_nonce(n1)
    return ks, id_a, id_b, n1


def encode_t_b(ks: bytes, id_a: str) -> bytes:
    return _validate_session_key(ks) + _encode_id(id_a)


def decode_t_b(data: bytes) -> tuple[bytes, str]:
    raw_data = _validate_serialized_data(data)
    if len(raw_data) < BLOCK_SIZE + 1:
        raise ProtocolError("BAD_FORMAT")
    ks = _validate_session_key(raw_data[:BLOCK_SIZE])
    id_a, end_position = _decode_id(raw_data, BLOCK_SIZE)
    if end_position != len(raw_data):
        raise ProtocolError("BAD_FORMAT")
    return ks, id_a


def build_kdc_request(id_a: str, id_b: str, n1: bytes) -> dict[str, Any]:
    validated_id_a = _validate_id(id_a)
    validated_id_b = _validate_id(id_b)
    if validated_id_a == validated_id_b:
        raise ProtocolError("BAD_FORMAT")
    return {
        "v": PROTOCOL_VERSION,
        "type": "KDC_REQ",
        "id_a": validated_id_a,
        "id_b": validated_id_b,
        "n1": _validate_nonce(n1).hex(),
    }


def parse_kdc_request(msg: dict[str, Any]) -> tuple[str, str, bytes]:
    parsed_message = parse_message(msg, "KDC_REQ")
    id_a = _validate_id(parsed_message["id_a"])
    id_b = _validate_id(parsed_message["id_b"])
    if id_a == id_b:
        raise ProtocolError("BAD_FORMAT")
    n1 = _parse_hex_value(parsed_message["n1"], NONCE_SIZE, False)
    return id_a, id_b, n1


def build_kdc_response(
    ka: bytes,
    kb: bytes,
    ks: bytes,
    id_a: str,
    id_b: str,
    n1: bytes,
) -> dict[str, Any]:
    return {
        "v": PROTOCOL_VERSION,
        "type": "KDC_RESP",
        "for_a": seal(ka, encode_r_a(ks, id_a, id_b, n1)),
        "ticket": seal(kb, encode_t_b(ks, id_a)),
    }


def open_kdc_response(
    msg: dict[str, Any], ka: bytes, id_a: str, id_b: str, n1: bytes
) -> tuple[bytes, dict[str, str]]:
    parsed_message = parse_message(msg, "KDC_RESP")
    _, _, normalized_ticket = _parse_envelope(parsed_message["ticket"])
    payload = unseal(ka, parsed_message["for_a"])
    ks, response_id_a, response_id_b, response_n1 = decode_r_a(payload)
    expected_id_a = _validate_id(id_a)
    expected_id_b = _validate_id(id_b)
    expected_n1 = _validate_nonce(n1)
    if not secrets.compare_digest(response_id_a, expected_id_a):
        raise ProtocolError("BAD_FORMAT")
    if not secrets.compare_digest(response_id_b, expected_id_b):
        raise ProtocolError("BAD_FORMAT")
    if not secrets.compare_digest(response_n1, expected_n1):
        raise ProtocolError("BAD_FORMAT")
    return ks, normalized_ticket


def open_ticket(ticket: dict[str, Any], kb: bytes, expected_id_a: str) -> tuple[bytes, str]:
    payload = unseal(kb, ticket)
    ks, id_a = decode_t_b(payload)
    if not secrets.compare_digest(id_a, _validate_id(expected_id_a)):
        raise ProtocolError("BAD_FORMAT")
    return ks, id_a


def build_ticket(ticket: dict[str, Any]) -> dict[str, Any]:
    _, _, normalized_ticket = _parse_envelope(ticket)
    return {"v": PROTOCOL_VERSION, "type": "TICKET", "ticket": normalized_ticket}


def build_challenge(ks: bytes, n2: bytes) -> dict[str, Any]:
    return {
        "v": PROTOCOL_VERSION,
        "type": "CHALLENGE",
        "body": seal(_validate_session_key(ks), _validate_nonce(n2)),
    }


def build_challenge_response(ks: bytes, n2: bytes) -> dict[str, Any]:
    validated_nonce = _validate_nonce(n2)
    response = f(int.from_bytes(validated_nonce, "big")).to_bytes(NONCE_SIZE, "big")
    return {
        "v": PROTOCOL_VERSION,
        "type": "CHALLENGE_RESP",
        "body": seal(_validate_session_key(ks), response),
    }


def check_challenge_response(ks: bytes, n2: bytes, msg: dict[str, Any]) -> bool:
    parsed_message = parse_message(msg, "CHALLENGE_RESP")
    received_response = unseal(_validate_session_key(ks), parsed_message["body"])
    if len(received_response) != NONCE_SIZE:
        raise ProtocolError("BAD_FORMAT")
    expected_response = f(int.from_bytes(_validate_nonce(n2), "big")).to_bytes(NONCE_SIZE, "big")
    return secrets.compare_digest(received_response, expected_response)


def build_app_msg(from_id: str, ks: bytes, plaintext: str) -> dict[str, Any]:
    return {
        "v": PROTOCOL_VERSION,
        "type": "APP_MSG",
        "from": _validate_id(from_id),
        "body": seal(_validate_session_key(ks), _validate_plaintext(plaintext)),
    }


def open_app_msg(
    msg: dict[str, Any], ks: bytes, expected_from: str | None = None
) -> tuple[str, str]:
    parsed_message = parse_message(msg, "APP_MSG")
    from_id = _validate_id(parsed_message["from"])
    if expected_from is not None and from_id != _validate_id(expected_from):
        raise ProtocolError("BAD_FORMAT")
    plaintext_bytes = unseal(_validate_session_key(ks), parsed_message["body"])
    try:
        plaintext = plaintext_bytes.decode("ascii")
    except UnicodeDecodeError as error:
        raise ProtocolError("BAD_FORMAT") from error
    _validate_plaintext(plaintext)
    return from_id, plaintext


def compute_kcv(ks: bytes) -> str:
    try:
        return encrypt_block(_validate_session_key(ks), bytes(BLOCK_SIZE))[:3].hex()
    except (AESError, TypeError) as error:
        raise ProtocolError("BAD_FORMAT") from error


def build_auth_ok() -> dict[str, Any]:
    return {"v": PROTOCOL_VERSION, "type": "AUTH_OK"}


def build_auth_fail(code: str) -> dict[str, Any]:
    return _build_error_message("AUTH_FAIL", code, AUTH_FAIL_CODES)


def build_error(code: str, msg: str = "") -> dict[str, Any]:
    return _build_error_message("ERROR", code, ERROR_CODES, msg)


def build_bye() -> dict[str, Any]:
    return {"v": PROTOCOL_VERSION, "type": "BYE"}


def build_kdc_error(code: str, msg: str = "") -> dict[str, Any]:
    return _build_error_message("KDC_ERR", code, KDC_ERROR_CODES, msg)


def parse_message(msg: dict[str, Any], expected_type: str | None = None) -> dict[str, Any]:
    if not isinstance(msg, dict):
        raise ProtocolError("BAD_FORMAT")
    version = msg.get("v")
    message_type = msg.get("type")
    if isinstance(version, bool) or not isinstance(version, int) or version != PROTOCOL_VERSION:
        raise ProtocolError("BAD_FORMAT")
    if not isinstance(message_type, str) or message_type not in MESSAGE_FIELDS:
        raise ProtocolError("BAD_FORMAT")
    if expected_type is not None and message_type != expected_type:
        raise ProtocolError("BAD_FORMAT")
    if set(msg) != MESSAGE_FIELDS[message_type]:
        raise ProtocolError("BAD_FORMAT")
    _validate_message_value_types(msg, message_type)
    return msg


def _build_error_message(
    message_type: str, code: str, allowed_codes: frozenset[str], msg: str | None = None
) -> dict[str, Any]:
    if not isinstance(code, str) or code not in allowed_codes:
        raise ProtocolError("BAD_FORMAT")
    result: dict[str, Any] = {"v": PROTOCOL_VERSION, "type": message_type, "code": code}
    if msg is not None:
        if not isinstance(msg, str):
            raise ProtocolError("BAD_FORMAT")
        result["msg"] = msg
    return result


def _validate_message_value_types(msg: dict[str, Any], message_type: str) -> None:
    if message_type == "KDC_REQ":
        _validate_id(msg["id_a"])
        _validate_id(msg["id_b"])
        _parse_hex_value(msg["n1"], NONCE_SIZE, False)
    elif message_type == "KDC_RESP":
        _parse_envelope(msg["for_a"])
        _parse_envelope(msg["ticket"])
    elif message_type == "TICKET":
        _parse_envelope(msg["ticket"])
    elif message_type in {"CHALLENGE", "CHALLENGE_RESP"}:
        _parse_envelope(msg["body"])
    elif message_type == "APP_MSG":
        _validate_id(msg["from"])
        _parse_envelope(msg["body"])
    elif message_type == "KDC_ERR":
        _validate_error_code(msg["code"], KDC_ERROR_CODES)
        _require_string(msg["msg"])
    elif message_type == "AUTH_FAIL":
        _validate_error_code(msg["code"], AUTH_FAIL_CODES)
    elif message_type == "ERROR":
        _validate_error_code(msg["code"], ERROR_CODES)
        _require_string(msg["msg"])


def _parse_envelope(envelope: Any) -> tuple[bytes, bytes, dict[str, str]]:
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise ProtocolError("BAD_FORMAT")
    iv = _parse_hex_value(envelope["iv"], BLOCK_SIZE, False)
    ciphertext = _parse_hex_value(envelope["ct"], BLOCK_SIZE, True)
    return iv, ciphertext, {"iv": iv.hex(), "ct": ciphertext.hex()}


def _parse_hex_value(value: Any, size: int, allow_multiple: bool) -> bytes:
    if not isinstance(value, str):
        raise ProtocolError("BAD_FORMAT")
    expected_length = size * 2
    if len(value) < expected_length or len(value) % expected_length != 0:
        raise ProtocolError("BAD_FORMAT")
    if not allow_multiple and len(value) != expected_length:
        raise ProtocolError("BAD_FORMAT")
    try:
        return hex_to_bytes(value)
    except ValueError as error:
        raise ProtocolError("BAD_FORMAT") from error


def _decode_id(data: bytes, position: int) -> tuple[str, int]:
    if position >= len(data):
        raise ProtocolError("BAD_FORMAT")
    id_length = data[position]
    end_position = position + 1 + id_length
    if not 1 <= id_length <= 16 or end_position > len(data):
        raise ProtocolError("BAD_FORMAT")
    try:
        identity = data[position + 1 : end_position].decode("ascii")
    except UnicodeDecodeError as error:
        raise ProtocolError("BAD_FORMAT") from error
    return _validate_id(identity), end_position


def _encode_id(identity: str) -> bytes:
    encoded_identity = _validate_id(identity).encode("ascii")
    return bytes((len(encoded_identity),)) + encoded_identity


def _validate_session_key(ks: bytes) -> bytes:
    _require_bytes(ks)
    try:
        validated_ks = validate_key(ks.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ProtocolError("BAD_FORMAT") from error
    return validated_ks


def _validate_cipher_key(key: bytes) -> bytes:
    _require_bytes(key)
    if len(key) != BLOCK_SIZE:
        raise ProtocolError("BAD_FORMAT")
    return key


def _validate_id(identity: Any) -> str:
    try:
        return validate_id(identity)
    except ValueError as error:
        raise ProtocolError("BAD_FORMAT") from error


def _validate_plaintext(plaintext: Any) -> bytes:
    try:
        return validate_plaintext(plaintext)
    except ValueError as error:
        raise ProtocolError("BAD_FORMAT") from error


def _validate_nonce(nonce: Any) -> bytes:
    _require_bytes(nonce)
    if len(nonce) != NONCE_SIZE:
        raise ProtocolError("BAD_FORMAT")
    return nonce


def _validate_serialized_data(data: Any) -> bytes:
    _require_bytes(data)
    return data


def _validate_iv(iv: Any) -> bytes:
    _require_bytes(iv)
    if len(iv) != BLOCK_SIZE:
        raise ProtocolError("BAD_FORMAT")
    return iv


def _validate_error_code(code: Any, allowed_codes: frozenset[str]) -> None:
    if not isinstance(code, str) or code not in allowed_codes:
        raise ProtocolError("BAD_FORMAT")


def _require_string(value: Any) -> str:
    if not isinstance(value, str):
        raise ProtocolError("BAD_FORMAT")
    return value


def _require_bytes(value: Any) -> bytes:
    if not isinstance(value, bytes):
        raise ProtocolError("BAD_FORMAT")
    return value

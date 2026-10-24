import re


ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,16}")
KEY_LENGTH = 16
MAX_PLAINTEXT_LENGTH = 1024


def bytes_to_hex(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return data.hex()


def hex_to_bytes(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("hex value must be a string")
    if len(value) % 2 != 0:
        raise ValueError("hex value must have an even length")
    if re.fullmatch(r"[0-9A-Fa-f]*", value) is None:
        raise ValueError("hex value contains invalid characters")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("hex value contains invalid characters") from error


def validate_key(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("key must be a string")
    if len(value) != KEY_LENGTH:
        raise ValueError("key must contain exactly 16 printable ASCII characters")
    if not _is_printable_ascii(value):
        raise ValueError("key must contain only printable ASCII characters")
    return value.encode("ascii")


def validate_plaintext(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("plaintext must be a string")
    if not 1 <= len(value) <= MAX_PLAINTEXT_LENGTH:
        raise ValueError("plaintext must contain 1 to 1024 characters")
    if not _is_printable_ascii(value):
        raise ValueError("plaintext must contain only printable ASCII characters")
    return value.encode("ascii")


def validate_id(value: str) -> str:
    if not isinstance(value, str) or ID_PATTERN.fullmatch(value) is None:
        raise ValueError("id must contain 1 to 16 letters, digits, underscores, or hyphens")
    return value


def _is_printable_ascii(value: str) -> bool:
    return all(0x20 <= ord(character) <= 0x7E for character in value)

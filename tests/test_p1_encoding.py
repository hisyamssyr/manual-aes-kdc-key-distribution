import unittest

from encoding_utils import (
    bytes_to_hex,
    hex_to_bytes,
    validate_id,
    validate_key,
    validate_plaintext,
)


class EncodingUtilsTests(unittest.TestCase):
    def test_hex_round_trip_normalizes_output(self) -> None:
        original = b"\x00\xab\xffhello"
        self.assertEqual(bytes_to_hex(original), "00abff68656c6c6f")
        self.assertEqual(hex_to_bytes("00ABff68656C6C6F"), original)
        self.assertEqual(bytes_to_hex(b""), "")
        self.assertEqual(hex_to_bytes(""), b"")

    def test_invalid_hex_is_rejected(self) -> None:
        for value in ("0", "abc", "gg", "00 0"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    hex_to_bytes(value)

    def test_key_requires_exact_printable_ascii_length(self) -> None:
        self.assertEqual(validate_key("1234567890abcdef"), b"1234567890abcdef")
        for value in ("1234567890abcde", "1234567890abcdefg", "1234567890abcde\n", "é" * 16):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_key(value)

    def test_plaintext_enforces_printable_ascii_boundaries(self) -> None:
        self.assertEqual(validate_plaintext(" "), b" ")
        self.assertEqual(validate_plaintext("x" * 1024), b"x" * 1024)
        for value in ("", "x" * 1025, "line\nbreak", "café"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_plaintext(value)

    def test_id_preserves_case_and_rejects_invalid_values(self) -> None:
        self.assertEqual(validate_id("Alice_1-B"), "Alice_1-B")
        for value in ("", "a" * 17, "alice!", "alice bob", "álìce"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_id(value)

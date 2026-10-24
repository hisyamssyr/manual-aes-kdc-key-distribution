import unittest

from manual_aes import (
    AESError,
    INV_S_BOX,
    S_BOX,
    decrypt_block,
    decrypt_cbc,
    encrypt_block,
    encrypt_cbc,
    expand_key,
    generate_iv,
    inv_mix_columns,
    inv_shift_rows,
    inv_sub_bytes,
    mix_columns,
    shift_rows,
    sub_bytes,
)


class ManualAesTests(unittest.TestCase):
    def test_s_boxes_are_generated_and_inverse(self) -> None:
        self.assertEqual(S_BOX[0x00], 0x63)
        self.assertEqual(S_BOX[0x53], 0xED)
        for value in range(256):
            self.assertEqual(INV_S_BOX[S_BOX[value]], value)

    def test_key_expansion_matches_fips_197_round_ten_key(self) -> None:
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        round_keys = expand_key(key)

        self.assertEqual(len(round_keys), 11)
        self.assertEqual(round_keys[10].hex(), "13111d7fe3944a17f307a78b4d2b30c5")

    def test_block_encryption_matches_fips_vectors(self) -> None:
        vectors = (
            (
                "2b7e151628aed2a6abf7158809cf4f3c",
                "3243f6a8885a308d313198a2e0370734",
                "3925841d02dc09fbdc118597196a0b32",
            ),
            (
                "000102030405060708090a0b0c0d0e0f",
                "00112233445566778899aabbccddeeff",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
        )
        for key_hex, plaintext_hex, ciphertext_hex in vectors:
            with self.subTest(key=key_hex):
                key = bytes.fromhex(key_hex)
                plaintext = bytes.fromhex(plaintext_hex)
                ciphertext = bytes.fromhex(ciphertext_hex)
                self.assertEqual(encrypt_block(key, plaintext), ciphertext)
                self.assertEqual(decrypt_block(key, ciphertext), plaintext)

    def test_inverse_transformations_restore_the_original_block(self) -> None:
        block = bytes(range(16))
        self.assertEqual(inv_sub_bytes(sub_bytes(block)), block)
        self.assertEqual(inv_shift_rows(shift_rows(block)), block)
        self.assertEqual(inv_mix_columns(mix_columns(block)), block)

    def test_cbc_prefix_matches_nist_sp_800_38a_vector(self) -> None:
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        expected_ciphertext = bytes.fromhex(
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7"
        )

        ciphertext = encrypt_cbc(key, iv, plaintext)

        self.assertEqual(ciphertext[: len(expected_ciphertext)], expected_ciphertext)
        self.assertEqual(decrypt_cbc(key, iv, ciphertext), plaintext)

    def test_cbc_round_trip_and_size_rule(self) -> None:
        key = b"0123456789abcdef"
        iv = b"fedcba9876543210"
        for length in range(101):
            with self.subTest(length=length):
                plaintext = bytes(index % 256 for index in range(length))
                ciphertext = encrypt_cbc(key, iv, plaintext)
                self.assertEqual(len(ciphertext), (length // 16 + 1) * 16)
                self.assertEqual(decrypt_cbc(key, iv, ciphertext), plaintext)

    def test_different_ivs_produce_different_ciphertexts(self) -> None:
        key = b"0123456789abcdef"
        plaintext = b"same plaintext"
        first_iv = bytes(16)
        second_iv = bytes((1,)) * 16

        self.assertNotEqual(
            encrypt_cbc(key, first_iv, plaintext),
            encrypt_cbc(key, second_iv, plaintext),
        )

    def test_invalid_padding_and_ciphertext_are_rejected(self) -> None:
        key = b"0123456789abcdef"
        iv = bytes(16)
        invalid_blocks = (
            bytes(15) + b"\x00",
            bytes(15) + b"\x11",
            bytes(14) + b"\x01\x02",
        )
        for invalid_block in invalid_blocks:
            with self.subTest(invalid_block=invalid_block):
                ciphertext = encrypt_block(key, invalid_block)
                with self.assertRaises(AESError):
                    decrypt_cbc(key, iv, ciphertext)

        for ciphertext in (b"", b"x", b"x" * 17):
            with self.subTest(ciphertext=ciphertext):
                with self.assertRaises(AESError):
                    decrypt_cbc(key, iv, ciphertext)

    def test_invalid_lengths_and_types_are_rejected(self) -> None:
        key = b"0123456789abcdef"
        block = bytes(16)
        for invalid_value in (b"short", b"x" * 17):
            with self.subTest(invalid_value=invalid_value):
                with self.assertRaises(AESError):
                    encrypt_block(invalid_value, block)
                with self.assertRaises(AESError):
                    decrypt_block(key, invalid_value)
                with self.assertRaises(AESError):
                    encrypt_cbc(key, invalid_value, b"")

        with self.assertRaises(TypeError):
            encrypt_block("not-bytes", block)
        with self.assertRaises(TypeError):
            decrypt_cbc(key, block, "not-bytes")

    def test_wrong_key_never_crashes(self) -> None:
        key = b"0123456789abcdef"
        wrong_key = b"abcdef0123456789"
        iv = bytes(16)
        ciphertext = encrypt_cbc(key, iv, b"message")
        try:
            decrypt_cbc(wrong_key, iv, ciphertext)
        except AESError:
            pass

    def test_generate_iv_returns_fresh_aes_block(self) -> None:
        first_iv = generate_iv()
        second_iv = generate_iv()
        self.assertEqual(len(first_iv), 16)
        self.assertEqual(len(second_iv), 16)
        self.assertNotEqual(first_iv, second_iv)

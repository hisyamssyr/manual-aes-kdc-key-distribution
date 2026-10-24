import json
import unittest

from manual_aes import encrypt_block
from protocol import (
    ProtocolError,
    build_app_msg,
    build_auth_fail,
    build_auth_ok,
    build_bye,
    build_challenge,
    build_challenge_response,
    build_error,
    build_kdc_error,
    build_kdc_request,
    build_kdc_response,
    build_ticket,
    check_challenge_response,
    compute_kcv,
    decode_r_a,
    decode_t_b,
    encode_r_a,
    encode_t_b,
    f,
    new_nonce,
    new_session_key,
    open_app_msg,
    open_kdc_response,
    open_ticket,
    parse_kdc_request,
    parse_message,
    seal,
    unseal,
)


class ProtocolTests(unittest.TestCase):
    KA = b"0123456789abcdef"
    KB = b"fedcba9876543210"
    KS = b"session-key-1234"
    N1 = bytes.fromhex("0102030405060708")
    N2 = bytes.fromhex("1020304050607080")
    IV = bytes.fromhex("00112233445566778899aabbccddeeff")

    def test_r_a_and_t_b_serialization_round_trip(self) -> None:
        r_a = encode_r_a(self.KS, "a", "peer_identifier1", self.N1)
        ticket = encode_t_b(self.KS, "alice")

        self.assertEqual(decode_r_a(r_a), (self.KS, "a", "peer_identifier1", self.N1))
        self.assertEqual(decode_t_b(ticket), (self.KS, "alice"))

    def test_serialization_rejects_malformed_data(self) -> None:
        encoded = encode_r_a(self.KS, "alice", "bob", self.N1)
        malformed_values = (encoded[:-1], encoded + b"x", bytes(16) + b"\x00")
        for malformed in malformed_values:
            with self.subTest(malformed=malformed):
                with self.assertRaises(ProtocolError) as captured:
                    decode_r_a(malformed)
                self.assertEqual(captured.exception.code, "BAD_FORMAT")

    def test_session_key_nonce_and_nonce_function_rules(self) -> None:
        session_key = new_session_key()
        nonce = new_nonce()

        self.assertEqual(len(session_key), 16)
        self.assertTrue(all(0x21 <= value <= 0x7E for value in session_key))
        self.assertEqual(len(nonce), 8)
        self.assertEqual(f(0), (1 << 64) - 1)
        self.assertEqual(f(1), 0)

    def test_seal_and_unseal_normalize_and_validate_envelopes(self) -> None:
        first = seal(self.KA, b"payload", iv=self.IV)
        second = seal(self.KA, b"payload")

        self.assertEqual(first["iv"], self.IV.hex())
        self.assertEqual(unseal(self.KA, first), b"payload")
        self.assertNotEqual(first, second)
        self.assertEqual(set(first), {"iv", "ct"})
        self.assertTrue(first["ct"].islower())

        malformed_envelopes = (
            {"iv": "00", "ct": first["ct"]},
            {"iv": self.IV.hex(), "ct": "00"},
            {"iv": self.IV.hex(), "ct": first["ct"], "extra": "x"},
        )
        for envelope in malformed_envelopes:
            with self.subTest(envelope=envelope):
                with self.assertRaises(ProtocolError) as captured:
                    unseal(self.KA, envelope)
                self.assertEqual(captured.exception.code, "BAD_FORMAT")

    def test_unseal_maps_invalid_padding_to_decrypt_fail(self) -> None:
        invalid_padded_data = bytes(15) + b"\x00"
        envelope = {"iv": bytes(16).hex(), "ct": encrypt_block(self.KA, invalid_padded_data).hex()}

        with self.assertRaises(ProtocolError) as captured:
            unseal(self.KA, envelope)

        self.assertEqual(captured.exception.code, "DECRYPT_FAIL")

    def test_kdc_request_build_and_parse(self) -> None:
        request = build_kdc_request("alice", "bob", self.N1)

        self.assertEqual(request["n1"], self.N1.hex())
        self.assertEqual(parse_kdc_request(request), ("alice", "bob", self.N1))
        request["id_b"] = "alice"
        with self.assertRaises(ProtocolError) as captured:
            parse_kdc_request(request)
        self.assertEqual(captured.exception.code, "BAD_FORMAT")

    def test_kdc_response_and_ticket_preserve_only_encrypted_key_material(self) -> None:
        response = build_kdc_response(self.KA, self.KB, self.KS, "alice", "bob", self.N1)
        response_json = json.dumps(response)
        opened_ks, ticket = open_kdc_response(response, self.KA, "alice", "bob", self.N1)

        self.assertEqual(opened_ks, self.KS)
        self.assertNotIn(self.KS.decode("ascii"), response_json)
        self.assertEqual(open_ticket(ticket, self.KB, "alice"), (self.KS, "alice"))
        self.assertEqual(build_ticket(ticket)["ticket"], ticket)

    def test_kdc_response_rejects_wrong_nonce_or_ticket_identity(self) -> None:
        response = build_kdc_response(self.KA, self.KB, self.KS, "alice", "bob", self.N1)
        with self.assertRaises(ProtocolError) as captured:
            open_kdc_response(response, self.KA, "alice", "bob", bytes(8))
        self.assertEqual(captured.exception.code, "BAD_FORMAT")

        ticket = seal(self.KB, encode_t_b(self.KS, "mallory"), iv=self.IV)
        with self.assertRaises(ProtocolError) as captured:
            open_ticket(ticket, self.KB, "alice")
        self.assertEqual(captured.exception.code, "BAD_FORMAT")

    def test_challenge_response_success_and_wrong_response(self) -> None:
        challenge = build_challenge(self.KS, self.N2)
        response = build_challenge_response(self.KS, self.N2)
        wrong_response = {
            "v": 1,
            "type": "CHALLENGE_RESP",
            "body": seal(self.KS, bytes(8), iv=self.IV),
        }

        self.assertEqual(unseal(self.KS, challenge["body"]), self.N2)
        self.assertTrue(check_challenge_response(self.KS, self.N2, response))
        self.assertFalse(check_challenge_response(self.KS, self.N2, wrong_response))

    def test_application_message_validation(self) -> None:
        message = build_app_msg("alice", self.KS, "hello world")

        self.assertEqual(open_app_msg(message, self.KS, "alice"), ("alice", "hello world"))
        with self.assertRaises(ProtocolError) as captured:
            open_app_msg(message, self.KS, "bob")
        self.assertEqual(captured.exception.code, "BAD_FORMAT")

        non_ascii_message = {
            "v": 1,
            "type": "APP_MSG",
            "from": "alice",
            "body": seal(self.KS, b"\xff", iv=self.IV),
        }
        with self.assertRaises(ProtocolError) as captured:
            open_app_msg(non_ascii_message, self.KS)
        self.assertEqual(captured.exception.code, "BAD_FORMAT")

    def test_message_schemas_reject_wrong_types_missing_fields_and_unknown_fields(self) -> None:
        invalid_messages = (
            {"v": True, "type": "AUTH_OK"},
            {"v": 1, "type": "UNKNOWN"},
            {"v": 1, "type": "AUTH_OK", "extra": "x"},
            {"v": 1, "type": "KDC_REQ", "id_a": "alice", "id_b": "bob"},
        )
        for message in invalid_messages:
            with self.subTest(message=message):
                with self.assertRaises(ProtocolError) as captured:
                    parse_message(message)
                self.assertEqual(captured.exception.code, "BAD_FORMAT")

    def test_status_and_error_builders_accept_only_allowed_codes(self) -> None:
        builders = (
            build_auth_ok(),
            build_auth_fail("TIMEOUT"),
            build_error("BUSY", "occupied"),
            build_bye(),
            build_kdc_error("UNKNOWN_ID", "not registered"),
        )
        for message in builders:
            with self.subTest(message_type=message["type"]):
                self.assertEqual(parse_message(message), message)
                json.dumps(message)

        for builder in (build_auth_fail, build_error, build_kdc_error):
            with self.subTest(builder=builder.__name__):
                with self.assertRaises(ProtocolError):
                    builder("NOT_ALLOWED")

    def test_compute_kcv_is_stable_lowercase_and_six_characters(self) -> None:
        kcv = compute_kcv(self.KS)

        self.assertEqual(kcv, compute_kcv(self.KS))
        self.assertEqual(len(kcv), 6)
        self.assertEqual(kcv, kcv.lower())

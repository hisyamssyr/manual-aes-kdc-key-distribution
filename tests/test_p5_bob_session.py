import logging
import socket
import tempfile
import threading
import time
import unittest
from typing import Any

from alice_client import authenticate_with_bob, request_session_key
from app_logging import configure_logging
from bob_client import BobServer
from kdc_server import KDCServer
from network import close_socket, connect, make_listener, recv_message, send_message
from protocol import (
    ProtocolError,
    build_challenge_response,
    build_ticket,
    encode_t_b,
    open_challenge,
    seal,
)
from session import AliceSession, AliceState, BobSession, BobState, StateError, assert_bob_transition


class TestBobSessionP5(unittest.TestCase):
    KA = b"alice_master_key"
    KB = b"bob_master_key__"
    KS = b"shared_session_k"

    def setUp(self: "TestBobSessionP5") -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.bob_log = f"{self.temp_dir.name}/bob.log"
        self.alice_log = f"{self.temp_dir.name}/alice.log"
        self.kdc_log = f"{self.temp_dir.name}/kdc.log"

        self.bob_logger = configure_logging("bob", self.bob_log, "DEBUG")
        self.alice_logger = configure_logging("alice", self.alice_log, "DEBUG")
        self.kdc_logger = configure_logging("kdc", self.kdc_log, "DEBUG")

        temp = socket.socket()
        temp.bind(("127.0.0.1", 0))
        self.bob_port = temp.getsockname()[1]
        temp.close()

        temp = socket.socket()
        temp.bind(("127.0.0.1", 0))
        self.kdc_port = temp.getsockname()[1]
        temp.close()

        self.kdc_cfg = {
            "listen": {"host": "127.0.0.1", "port": self.kdc_port},
            "registry_ids": ["alice", "bob"],
            "timeouts": {"connect": 2.0, "step": 2.0},
            "logging": {"file": self.kdc_log, "level": "DEBUG"},
        }
        self.bob_cfg = {
            "id": "bob",
            "peer_id": "alice",
            "listen": {"host": "127.0.0.1", "port": self.bob_port},
            "timeouts": {"connect": 2.0, "step": 2.0},
            "logging": {"file": self.bob_log, "level": "DEBUG"},
        }
        self.alice_cfg = {
            "id": "alice",
            "peer_id": "bob",
            "kdc": {"host": "127.0.0.1", "port": self.kdc_port},
            "bob": {"host": "127.0.0.1", "port": self.bob_port},
            "timeouts": {"connect": 2.0, "step": 2.0},
            "logging": {"file": self.alice_log, "level": "DEBUG"},
        }
        self.bob_server: BobServer | None = None
        self.kdc_server: KDCServer | None = None

    def tearDown(self: "TestBobSessionP5") -> None:
        if self.bob_server:
            self.bob_server.stop()
        if self.kdc_server:
            self.kdc_server.stop()
        for log in (self.bob_logger, self.alice_logger, self.kdc_logger):
            for h in list(log.handlers):
                h.close()
                log.removeHandler(h)
        logging.shutdown()
        self.temp_dir.cleanup()

    def _start_bob(self: "TestBobSessionP5", kb: bytes | None = None) -> BobServer:
        self.bob_server = BobServer(self.bob_cfg, kb or self.KB, self.bob_logger)
        self.bob_server.start()
        time.sleep(0.05)
        return self.bob_server

    def _start_kdc(self: "TestBobSessionP5") -> KDCServer:
        self.kdc_server = KDCServer(self.kdc_cfg, {"alice": self.KA, "bob": self.KB}, self.kdc_logger)
        self.kdc_server.start()
        time.sleep(0.05)
        return self.kdc_server

    def _make_ticket(self: "TestBobSessionP5", kb: bytes, id_a: str = "alice", ks: bytes = KS) -> dict[str, Any]:
        return seal(kb, encode_t_b(ks, id_a))

    def test_t5_1_full_flow_steps_1_to_5(self: "TestBobSessionP5") -> None:
        self._start_kdc()
        bob = self._start_bob()
        alice_session = AliceSession()

        request_session_key(self.alice_cfg, self.KA, alice_session, self.alice_logger)
        self.assertEqual(alice_session.state, AliceState.KEY_READY)

        alice_sock = authenticate_with_bob(self.alice_cfg, alice_session, self.alice_logger)
        self.assertEqual(alice_session.state, AliceState.AUTHENTICATED)
        self.assertEqual(bob.session.state, BobState.AUTHENTICATED)
        self.assertEqual(alice_session.ks, bob.session.ks)
        close_socket(alice_sock)

    def test_t5_2_bob_rejects_wrong_kb(self: "TestBobSessionP5") -> None:
        self._start_bob(kb=b"different_bob_k_")
        session = AliceSession(state=AliceState.KEY_READY, ks=self.KS, ticket=self._make_ticket(self.KB))

        with self.assertRaises(ProtocolError) as ctx:
            authenticate_with_bob(self.alice_cfg, session)

        self.assertEqual(ctx.exception.code, "DECRYPT_FAIL")
        self.assertEqual(session.state, AliceState.IDLE)
        self.assertIsNone(session.ks)

    def test_t5_3_ticket_tampered_in_transit(self: "TestBobSessionP5") -> None:
        self._start_bob()
        tampered = self._make_ticket(self.KB)
        tampered["ct"] = "ff" * len(tampered["ct"])
        session = AliceSession(state=AliceState.KEY_READY, ks=self.KS, ticket=tampered)

        with self.assertRaises(ProtocolError):
            authenticate_with_bob(self.alice_cfg, session)
        self.assertEqual(session.state, AliceState.IDLE)

    def test_t5_4_wrong_id_a_in_ticket(self: "TestBobSessionP5") -> None:
        self._start_bob()
        wrong_id_ticket = self._make_ticket(self.KB, id_a="eve")
        session = AliceSession(state=AliceState.KEY_READY, ks=self.KS, ticket=wrong_id_ticket)

        with self.assertRaises(ProtocolError) as ctx:
            authenticate_with_bob(self.alice_cfg, session)
        self.assertEqual(ctx.exception.code, "BAD_FORMAT")
        self.assertEqual(session.state, AliceState.IDLE)

    def test_t5_5_wrong_challenge_response(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        sock = connect("127.0.0.1", self.bob_port, timeout=1.0)
        send_message(sock, build_ticket(self._make_ticket(self.KB)))

        recv_message(sock, timeout=1.0)
        send_message(sock, build_challenge_response(self.KS, b"\x00" * 8))

        resp = recv_message(sock, timeout=1.0)
        self.assertEqual(resp.get("code"), "BAD_RESPONSE")
        self.assertEqual(srv.session.state, BobState.LISTENING)
        close_socket(sock)

    def test_t5_6_corrupted_challenge_response_payload(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        sock = connect("127.0.0.1", self.bob_port, timeout=1.0)
        send_message(sock, build_ticket(self._make_ticket(self.KB)))
        recv_message(sock, timeout=1.0)

        send_message(sock, {"v": 1, "type": "CHALLENGE_RESP", "body": "invalid_body"})
        resp = recv_message(sock, timeout=1.0)
        self.assertEqual(resp.get("code"), "BAD_FORMAT")
        self.assertEqual(srv.session.state, BobState.LISTENING)
        close_socket(sock)

    def test_t5_7_challenge_response_timeout(self: "TestBobSessionP5") -> None:
        self.bob_cfg["timeouts"]["step"] = 0.2
        srv = self._start_bob()
        sock = connect("127.0.0.1", self.bob_port, timeout=1.0)
        send_message(sock, build_ticket(self._make_ticket(self.KB)))
        recv_message(sock, timeout=1.0)

        resp = recv_message(sock, timeout=1.0)
        self.assertEqual(resp.get("code"), "TIMEOUT")
        self.assertEqual(srv.session.state, BobState.LISTENING)
        close_socket(sock)

    def test_t5_8_bob_silent_alice_timeout(self: "TestBobSessionP5") -> None:
        listener = make_listener("127.0.0.1", self.bob_port)
        def _silent() -> None:
            s, _ = listener.accept()
            time.sleep(0.3)
            close_socket(s)
            close_socket(listener)

        threading.Thread(target=_silent, daemon=True).start()
        cfg = dict(self.alice_cfg, timeouts={"connect": 0.5, "step": 0.1})
        session = AliceSession(state=AliceState.KEY_READY, ks=self.KS, ticket=self._make_ticket(self.KB))

        with self.assertRaises(Exception):
            authenticate_with_bob(cfg, session)
        self.assertEqual(session.state, AliceState.IDLE)

    def test_t5_9_pre_auth_message_rejected(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        sock = connect("127.0.0.1", self.bob_port, timeout=1.0)
        send_message(sock, {"v": 1, "type": "APP_MSG", "from": "alice", "body": {"iv": "00", "ct": "00"}})

        resp = recv_message(sock, timeout=1.0)
        self.assertEqual(resp.get("code"), "BAD_STATE")
        self.assertEqual(srv.session.state, BobState.LISTENING)
        close_socket(sock)

    def test_t5_10_second_ticket_during_active_session_rejected(self: "TestBobSessionP5") -> None:
        self._start_bob()
        session = AliceSession(state=AliceState.KEY_READY, ks=self.KS, ticket=self._make_ticket(self.KB))
        sock = authenticate_with_bob(self.alice_cfg, session)

        send_message(sock, build_ticket(self._make_ticket(self.KB)))
        resp = recv_message(sock, timeout=1.0)
        self.assertEqual(resp.get("code"), "BAD_STATE")
        close_socket(sock)

    def test_t5_11_and_t5_18_busy_rejection_second_connection(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        session = AliceSession(state=AliceState.KEY_READY, ks=self.KS, ticket=self._make_ticket(self.KB))
        sock1 = authenticate_with_bob(self.alice_cfg, session)

        self.assertEqual(srv.session.state, BobState.AUTHENTICATED)

        sock2 = connect("127.0.0.1", self.bob_port, timeout=1.0)
        busy_resp = recv_message(sock2, timeout=1.0)
        self.assertEqual(busy_resp.get("code"), "BUSY")

        self.assertEqual(srv.session.state, BobState.AUTHENTICATED)
        close_socket(sock1)
        close_socket(sock2)

    def test_t5_12_bob_offline_keeps_alice_key_ready(self: "TestBobSessionP5") -> None:
        session = AliceSession(state=AliceState.KEY_READY, ks=self.KS, ticket=self._make_ticket(self.KB))
        with self.assertRaises(Exception):
            authenticate_with_bob(self.alice_cfg, session)
        self.assertEqual(session.state, AliceState.KEY_READY)
        self.assertIsNotNone(session.ks)
        self.assertIsNotNone(session.ticket)

    def test_t5_13_two_consecutive_sessions_distinct_nonces(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        s1 = connect("127.0.0.1", self.bob_port, timeout=1.0)
        send_message(s1, build_ticket(self._make_ticket(self.KB)))
        ch1 = recv_message(s1, timeout=1.0)
        n2_first = open_challenge(self.KS, ch1)
        send_message(s1, build_challenge_response(self.KS, n2_first))
        recv_message(s1, timeout=1.0)
        close_socket(s1)
        srv.session.reset_to_listening()

        s2 = connect("127.0.0.1", self.bob_port, timeout=1.0)
        send_message(s2, build_ticket(self._make_ticket(self.KB)))
        ch2 = recv_message(s2, timeout=1.0)
        n2_second = open_challenge(self.KS, ch2)
        close_socket(s2)

        self.assertNotEqual(n2_first, n2_second)

    def test_t5_14_and_t5_21_state_guards(self: "TestBobSessionP5") -> None:
        with self.assertRaises(StateError):
            assert_bob_transition(BobState.LISTENING, BobState.AUTHENTICATED)

        session = AliceSession(state=AliceState.IDLE)
        with self.assertRaises(StateError):
            authenticate_with_bob(self.alice_cfg, session)

    def test_t5_15_reference_hygiene_post_failure(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        sock = connect("127.0.0.1", self.bob_port, timeout=1.0)
        send_message(sock, build_ticket(self._make_ticket(b"wrong_key_______")))
        recv_message(sock, timeout=1.0)

        self.assertIsNone(srv.session.ks)
        self.assertIsNone(srv.session.n2)
        self.assertEqual(srv.session.state, BobState.LISTENING)
        close_socket(sock)

    def test_t5_16_log_redaction(self: "TestBobSessionP5") -> None:
        self._start_bob()
        session = AliceSession(state=AliceState.KEY_READY, ks=self.KS, ticket=self._make_ticket(self.KB))
        sock = authenticate_with_bob(self.alice_cfg, session, self.alice_logger)

        with open(self.bob_log, "r", encoding="utf-8") as f1, open(self.alice_log, "r", encoding="utf-8") as f2:
            logs = f1.read() + f2.read()

        for secret in (self.KB.decode(), self.KS.decode()):
            self.assertNotIn(secret, logs)
        close_socket(sock)

    def test_t5_20_shutdown_during_active_session(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        session = AliceSession(state=AliceState.KEY_READY, ks=self.KS, ticket=self._make_ticket(self.KB))
        sock = authenticate_with_bob(self.alice_cfg, session)

        t0 = time.time()
        srv.stop()
        self.assertLessEqual(time.time() - t0, 2.5)
        bye = recv_message(sock, timeout=1.0)
        self.assertEqual(bye.get("type"), "BYE")
        close_socket(sock)

    def test_t5_22_change_key_disconnects_active_session(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        session = AliceSession(state=AliceState.KEY_READY, ks=self.KS, ticket=self._make_ticket(self.KB))
        sock = authenticate_with_bob(self.alice_cfg, session)

        srv.change_key(b"brand_new_key___")
        self.assertEqual(srv.session.state, BobState.LISTENING)
        self.assertIsNone(srv.session.ks)

        bye = recv_message(sock, timeout=1.0)
        self.assertEqual(bye.get("type"), "BYE")
        close_socket(sock)

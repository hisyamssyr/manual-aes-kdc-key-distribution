import logging
import socket
import tempfile
import time
import unittest
from typing import Any

from bob_client import BobServer
from network import close_socket, connect, recv_message, send_message
from protocol import (
    build_challenge_response,
    build_ticket,
    decode_t_b,
    encode_t_b,
    open_challenge,
    seal,
)
from session import BobSession, BobState, StateError, assert_bob_transition


class TestBobSessionP5(unittest.TestCase):
    KB = b"bob_master_key__"
    KS = b"shared_session_k"

    def setUp(self: "TestBobSessionP5") -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = f"{self.temp_dir.name}/bob.log"
        self.logger = logging.getLogger("test_bob")
        self.logger.setLevel(logging.DEBUG)

        temp = socket.socket()
        temp.bind(("127.0.0.1", 0))
        self.bob_port = temp.getsockname()[1]
        temp.close()

        self.bob_cfg = {
            "id": "bob",
            "peer_id": "alice",
            "listen": {"host": "127.0.0.1", "port": self.bob_port},
            "timeouts": {"connect": 2.0, "step": 2.0},
            "logging": {"file": self.log_path, "level": "DEBUG"},
        }
        self.server: BobServer | None = None

    def tearDown(self: "TestBobSessionP5") -> None:
        if self.server:
            self.server.stop()
        for h in list(self.logger.handlers):
            h.close()
            self.logger.removeHandler(h)
        logging.shutdown()
        self.temp_dir.cleanup()

    def _start_bob(self: "TestBobSessionP5", kb: bytes | None = None) -> BobServer:
        self.server = BobServer(self.bob_cfg, kb or self.KB, self.logger)
        self.server.start()
        time.sleep(0.05)
        return self.server

    def _make_ticket(self: "TestBobSessionP5", kb: bytes, id_a: str = "alice", ks: bytes = KS) -> dict[str, Any]:
        return seal(kb, encode_t_b(ks, id_a))

    def test_bob_handshake_success(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        sock = connect("127.0.0.1", self.bob_port, timeout=1.0)

        ticket_envelope = self._make_ticket(self.KB, "alice", self.KS)
        send_message(sock, build_ticket(ticket_envelope))

        challenge = recv_message(sock, timeout=1.0)
        self.assertEqual(challenge.get("type"), "CHALLENGE")

        n2 = open_challenge(self.KS, challenge)
        send_message(sock, build_challenge_response(self.KS, n2))

        auth_ok = recv_message(sock, timeout=1.0)
        self.assertEqual(auth_ok.get("type"), "AUTH_OK")

        self.assertEqual(srv.session.state, BobState.AUTHENTICATED)
        self.assertEqual(srv.session.ks, self.KS)
        close_socket(sock)

    def test_bob_rejects_wrong_kb(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        sock = connect("127.0.0.1", self.bob_port, timeout=1.0)

        wrong_ticket = self._make_ticket(b"wrong_bob_key___", "alice", self.KS)
        send_message(sock, build_ticket(wrong_ticket))

        resp = recv_message(sock, timeout=1.0)
        self.assertEqual(resp.get("type"), "AUTH_FAIL")
        self.assertEqual(resp.get("code"), "DECRYPT_FAIL")
        self.assertEqual(srv.session.state, BobState.LISTENING)
        close_socket(sock)

    def test_bob_rejects_wrong_id_a(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        sock = connect("127.0.0.1", self.bob_port, timeout=1.0)

        imposter_ticket = self._make_ticket(self.KB, "eve", self.KS)
        send_message(sock, build_ticket(imposter_ticket))

        resp = recv_message(sock, timeout=1.0)
        self.assertEqual(resp.get("type"), "AUTH_FAIL")
        self.assertEqual(resp.get("code"), "BAD_FORMAT")
        self.assertEqual(srv.session.state, BobState.LISTENING)
        close_socket(sock)

    def test_bob_rejects_wrong_challenge_response(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        sock = connect("127.0.0.1", self.bob_port, timeout=1.0)

        ticket_envelope = self._make_ticket(self.KB, "alice", self.KS)
        send_message(sock, build_ticket(ticket_envelope))

        challenge = recv_message(sock, timeout=1.0)
        self.assertEqual(challenge.get("type"), "CHALLENGE")

        wrong_n2 = b"\x00" * 8
        send_message(sock, build_challenge_response(self.KS, wrong_n2))

        resp = recv_message(sock, timeout=1.0)
        self.assertEqual(resp.get("type"), "AUTH_FAIL")
        self.assertEqual(resp.get("code"), "BAD_RESPONSE")
        self.assertEqual(srv.session.state, BobState.LISTENING)
        close_socket(sock)

    def test_bob_rejects_pre_auth_message(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        sock = connect("127.0.0.1", self.bob_port, timeout=1.0)

        send_message(sock, {"v": 1, "type": "APP_MSG", "from": "alice", "body": {"iv": "00", "ct": "00"}})
        resp = recv_message(sock, timeout=1.0)
        self.assertEqual(resp.get("type"), "ERROR")
        self.assertEqual(resp.get("code"), "BAD_STATE")
        self.assertEqual(srv.session.state, BobState.LISTENING)
        close_socket(sock)

    def test_bob_busy_rejection(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        s1 = connect("127.0.0.1", self.bob_port, timeout=1.0)
        send_message(s1, build_ticket(self._make_ticket(self.KB, "alice", self.KS)))
        ch = recv_message(s1, timeout=1.0)
        n2 = open_challenge(self.KS, ch)
        send_message(s1, build_challenge_response(self.KS, n2))
        recv_message(s1, timeout=1.0)

        self.assertEqual(srv.session.state, BobState.AUTHENTICATED)

        s2 = connect("127.0.0.1", self.bob_port, timeout=1.0)
        busy_resp = recv_message(s2, timeout=1.0)
        self.assertEqual(busy_resp.get("type"), "ERROR")
        self.assertEqual(busy_resp.get("code"), "BUSY")

        self.assertEqual(srv.session.state, BobState.AUTHENTICATED)
        close_socket(s1)
        close_socket(s2)

    def test_bob_change_key_disconnects_session(self: "TestBobSessionP5") -> None:
        srv = self._start_bob()
        s1 = connect("127.0.0.1", self.bob_port, timeout=1.0)
        send_message(s1, build_ticket(self._make_ticket(self.KB, "alice", self.KS)))
        ch = recv_message(s1, timeout=1.0)
        send_message(s1, build_challenge_response(self.KS, open_challenge(self.KS, ch)))
        recv_message(s1, timeout=1.0)

        self.assertEqual(srv.session.state, BobState.AUTHENTICATED)

        new_kb = b"new_bob_master_k"
        srv.change_key(new_kb)

        self.assertEqual(srv.session.state, BobState.LISTENING)
        self.assertIsNone(srv.session.ks)

        bye_msg = recv_message(s1, timeout=1.0)
        self.assertEqual(bye_msg.get("type"), "BYE")
        close_socket(s1)

    def test_bob_transition_guards(self: "TestBobSessionP5") -> None:
        with self.assertRaises(StateError):
            assert_bob_transition(BobState.LISTENING, BobState.AUTHENTICATED)

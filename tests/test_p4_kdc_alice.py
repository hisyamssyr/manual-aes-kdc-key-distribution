import logging
import socket
import struct
import tempfile
import threading
import time
import unittest
from typing import Any
from unittest.mock import patch

from alice_client import request_session_key
from app_logging import configure_logging
from kdc_server import KDCServer, prompt_key_for_id
from network import close_socket, connect, make_listener, recv_message, send_message
from protocol import ProtocolError, build_kdc_request, build_kdc_response, open_ticket
from session import AliceSession, AliceState, StateError


class TestKDCAndAliceP4(unittest.TestCase):
    KA = b"alice_master_key"
    KB = b"bob_master_key__"

    def setUp(self: "TestKDCAndAliceP4") -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.kdc_log = f"{self.temp_dir.name}/kdc.log"
        self.alice_log = f"{self.temp_dir.name}/alice.log"
        self.kdc_logger = configure_logging("kdc", self.kdc_log, "DEBUG")
        self.alice_logger = configure_logging("alice", self.alice_log, "DEBUG")

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
        self.alice_cfg = {
            "id": "alice",
            "peer_id": "bob",
            "kdc": {"host": "127.0.0.1", "port": self.kdc_port},
            "bob": {"host": "127.0.0.1", "port": 5001},
            "timeouts": {"connect": 2.0, "step": 2.0},
            "logging": {"file": self.alice_log, "level": "DEBUG"},
        }
        self.server: KDCServer | None = None

    def tearDown(self: "TestKDCAndAliceP4") -> None:
        if self.server:
            self.server.stop()
        for log in (self.kdc_logger, self.alice_logger):
            for h in list(log.handlers):
                h.close()
                log.removeHandler(h)
        logging.shutdown()
        self.temp_dir.cleanup()

    def _start_server(self: "TestKDCAndAliceP4", keys: dict[str, bytes] | None = None) -> KDCServer:
        self.server = KDCServer(self.kdc_cfg, keys or {"alice": self.KA, "bob": self.KB}, self.kdc_logger)
        self.server.start()
        time.sleep(0.05)
        return self.server

    def test_t4_1_successful_session_key(self: "TestKDCAndAliceP4") -> None:
        self._start_server()
        session = AliceSession()
        ks, ticket = request_session_key(self.alice_cfg, self.KA, session, self.alice_logger)
        self.assertEqual(session.state, AliceState.KEY_READY)
        self.assertEqual(len(ks), 16)
        self.assertTrue("iv" in ticket and "ct" in ticket)

    def test_t4_2_consecutive_requests_distinct(self: "TestKDCAndAliceP4") -> None:
        self._start_server()
        session = AliceSession()
        k1, t1 = request_session_key(self.alice_cfg, self.KA, session)
        k2, t2 = request_session_key(self.alice_cfg, self.KA, session)
        self.assertNotEqual(k1, k2)
        self.assertNotEqual(t1["iv"], t2["iv"])

    def test_t4_3_ticket_decryption_with_kb(self: "TestKDCAndAliceP4") -> None:
        self._start_server()
        ks, ticket = request_session_key(self.alice_cfg, self.KA)
        dec_ks, id_a = open_ticket(ticket, self.KB, "alice")
        self.assertEqual(dec_ks, ks)
        self.assertEqual(id_a, "alice")

    def test_t4_4_fake_kdc_wrong_nonce(self: "TestKDCAndAliceP4") -> None:
        def _fake(s: socket.socket) -> None:
            req = recv_message(s)
            send_message(s, build_kdc_response(self.KA, self.KB, b"dummy_session_12", req["id_a"], req["id_b"], b"\x00" * 8))
        self._run_fake_server(_fake)
        session = AliceSession()
        with self.assertRaises(ProtocolError):
            request_session_key(self.alice_cfg, self.KA, session)
        self.assertEqual(session.state, AliceState.IDLE)

    def test_t4_5_fake_kdc_wrong_peer(self: "TestKDCAndAliceP4") -> None:
        def _fake(s: socket.socket) -> None:
            req = recv_message(s)
            send_message(s, build_kdc_response(self.KA, self.KB, b"dummy_session_12", req["id_a"], "charlie", bytes.fromhex(req["n1"])))
        self._run_fake_server(_fake)
        session = AliceSession()
        with self.assertRaises(ProtocolError):
            request_session_key(self.alice_cfg, self.KA, session)
        self.assertEqual(session.state, AliceState.IDLE)

    def _run_fake_server(self: "TestKDCAndAliceP4", handler: Any) -> None:
        listener = make_listener("127.0.0.1", self.kdc_port)
        def _serve() -> None:
            sock, _ = listener.accept()
            try:
                handler(sock)
            finally:
                close_socket(sock)
                close_socket(listener)
        t = threading.Thread(target=_serve, daemon=True)
        t.start()

    def test_t4_6_wrong_ka_fails(self: "TestKDCAndAliceP4") -> None:
        self._start_server()
        session = AliceSession()
        with self.assertRaises(Exception):
            request_session_key(self.alice_cfg, b"wrong_master_key", session)
        self.assertEqual(session.state, AliceState.IDLE)

    def test_t4_7_unknown_id(self: "TestKDCAndAliceP4") -> None:
        self._start_server()
        cfg = dict(self.alice_cfg, peer_id="unknown_user")
        session = AliceSession()
        with self.assertRaises(ProtocolError) as ctx:
            request_session_key(cfg, self.KA, session)
        self.assertEqual(ctx.exception.code, "UNKNOWN_ID")
        self.assertEqual(session.state, AliceState.IDLE)

    def test_t4_8_malformed_request(self: "TestKDCAndAliceP4") -> None:
        self._start_server()
        s = connect("127.0.0.1", self.kdc_port, timeout=1.0)
        send_message(s, {"v": 1, "type": "KDC_REQ", "id_a": "alice", "id_b": "alice"})
        resp = recv_message(s, timeout=1.0)
        self.assertEqual(resp.get("code"), "BAD_FORMAT")
        close_socket(s)

        s2 = connect("127.0.0.1", self.kdc_port, timeout=1.0)
        s2.sendall(struct.pack("!I", 10) + b"not_json!!")
        time.sleep(0.05)
        close_socket(s2)

    def test_t4_9_oversized_payload(self: "TestKDCAndAliceP4") -> None:
        self._start_server()
        s = connect("127.0.0.1", self.kdc_port, timeout=1.0)
        s.sendall(struct.pack("!I", 70000) + b"A" * 100)
        time.sleep(0.05)
        close_socket(s)
        ks, _ = request_session_key(self.alice_cfg, self.KA)
        self.assertEqual(len(ks), 16)

    def test_t4_10_kdc_offline(self: "TestKDCAndAliceP4") -> None:
        session = AliceSession()
        with self.assertRaises(Exception):
            request_session_key(self.alice_cfg, self.KA, session)
        self.assertEqual(session.state, AliceState.IDLE)

    def test_t4_11_kdc_timeout(self: "TestKDCAndAliceP4") -> None:
        self._run_fake_server(lambda s: time.sleep(0.4))
        cfg = dict(self.alice_cfg, timeouts={"connect": 0.5, "step": 0.1})
        session = AliceSession()
        with self.assertRaises(Exception):
            request_session_key(cfg, self.KA, session)
        self.assertEqual(session.state, AliceState.IDLE)

    def test_t4_12_concurrent_requests(self: "TestKDCAndAliceP4") -> None:
        self._start_server()
        results: list[bytes] = []
        def _req() -> None:
            ks, _ = request_session_key(self.alice_cfg, self.KA)
            results.append(ks)
        t1, t2 = threading.Thread(target=_req), threading.Thread(target=_req)
        t1.start(); t2.start(); t1.join(2.0); t2.join(2.0)
        self.assertEqual(len(results), 2)
        self.assertNotEqual(results[0], results[1])

    def test_t4_13_dynamic_key_change(self: "TestKDCAndAliceP4") -> None:
        srv = self._start_server()
        new_ka = b"new_alice_key___"
        srv.change_key("alice", new_ka)
        with self.assertRaises(Exception):
            request_session_key(self.alice_cfg, self.KA)
        ks, _ = request_session_key(self.alice_cfg, new_ka)
        self.assertEqual(len(ks), 16)

    def test_t4_14_log_redaction(self: "TestKDCAndAliceP4") -> None:
        self._start_server()
        ks, _ = request_session_key(self.alice_cfg, self.KA, logger=self.alice_logger)
        with open(self.kdc_log, "r", encoding="utf-8") as f1, open(self.alice_log, "r", encoding="utf-8") as f2:
            logs = f1.read() + f2.read()
        for secret in (self.KA.decode(), self.KB.decode(), ks.decode()):
            self.assertNotIn(secret, logs)

    def test_t4_16_prompt_key_validation(self: "TestKDCAndAliceP4") -> None:
        with patch("getpass.getpass", side_effect=["invalid", "invalid", "valid_key_123456", "valid_key_123456"]):
            self.assertEqual(prompt_key_for_id("alice"), b"valid_key_123456")
        with patch("getpass.getpass", side_effect=["m1", "m2"] * 3), patch("sys.exit") as mock_exit:
            prompt_key_for_id("alice")
            mock_exit.assert_called_with(2)

    def test_t4_17_concurrent_key_change_and_request(self: "TestKDCAndAliceP4") -> None:
        srv = self._start_server()
        t = threading.Thread(target=lambda: (time.sleep(0.01), srv.change_key("alice", b"updated_key_1234")), daemon=True)
        t.start()
        try:
            request_session_key(self.alice_cfg, self.KA)
        except Exception:
            pass
        t.join(1.0)

    def test_t4_18_client_disconnects_mid_request(self: "TestKDCAndAliceP4") -> None:
        self._start_server()
        s = connect("127.0.0.1", self.kdc_port, timeout=1.0)
        s.sendall(struct.pack("!I", 100))
        s.close()
        time.sleep(0.05)
        ks, _ = request_session_key(self.alice_cfg, self.KA)
        self.assertEqual(len(ks), 16)

    def test_t4_19_state_guards(self: "TestKDCAndAliceP4") -> None:
        session = AliceSession(state=AliceState.REQUESTED)
        with self.assertRaises(StateError):
            request_session_key(self.alice_cfg, self.KA, session)

    def test_t4_20_shutdown_with_active_connection(self: "TestKDCAndAliceP4") -> None:
        srv = self._start_server()
        s = connect("127.0.0.1", self.kdc_port, timeout=1.0)
        t0 = time.time()
        srv.stop()
        self.assertLessEqual(time.time() - t0, 2.5)
        close_socket(s)

    def test_t4_21_internal_error_handling(self: "TestKDCAndAliceP4") -> None:
        self._start_server()
        with patch("kdc_server.build_kdc_response", side_effect=RuntimeError("unexpected")):
            s = connect("127.0.0.1", self.kdc_port, timeout=1.0)
            send_message(s, build_kdc_request("alice", "bob", b"\x01" * 8))
            resp = recv_message(s, timeout=1.0)
            self.assertEqual(resp.get("code"), "INTERNAL")
            close_socket(s)

    def test_t4_22_request_new_session_key_from_key_ready(self: "TestKDCAndAliceP4") -> None:
        self._start_server()
        session = AliceSession()
        k1, t1 = request_session_key(self.alice_cfg, self.KA, session)
        self.assertEqual(session.state, AliceState.KEY_READY)
        k2, t2 = request_session_key(self.alice_cfg, self.KA, session)
        self.assertEqual(session.state, AliceState.KEY_READY)
        self.assertNotEqual(k1, k2)
        self.assertNotEqual(t1["iv"], t2["iv"])

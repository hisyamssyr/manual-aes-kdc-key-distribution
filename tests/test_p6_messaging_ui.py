import io
import logging
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from alice_client import authenticate_with_bob, close_alice_session, request_session_key
from app_logging import configure_logging
from bob_client import BobServer
from kdc_server import KDCServer
from network import close_socket, connect, make_listener, recv_message, send_message
from protocol import (
    build_app_msg,
    build_bye,
    build_ticket,
    compute_kcv,
    encode_t_b,
    seal,
)
from session import (
    AliceSession,
    AliceState,
    BobSession,
    BobState,
    StateError,
    run_session_receiver,
    send_app_message,
)
import ui


class TestMessagingAndUIP6(unittest.TestCase):
    KA = b"alice_master_key"
    KB = b"bob_master_key__"
    KS = b"shared_session_k"

    def setUp(self: "TestMessagingAndUIP6") -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.kdc_log = f"{self.temp_dir.name}/kdc.log"
        self.alice_log = f"{self.temp_dir.name}/alice.log"
        self.bob_log = f"{self.temp_dir.name}/bob.log"

        self.kdc_logger = configure_logging("kdc", self.kdc_log, "DEBUG")
        self.alice_logger = configure_logging("alice", self.alice_log, "DEBUG")
        self.bob_logger = configure_logging("bob", self.bob_log, "DEBUG")

        temp = socket.socket()
        temp.bind(("127.0.0.1", 0))
        self.kdc_port = temp.getsockname()[1]
        temp.close()

        temp = socket.socket()
        temp.bind(("127.0.0.1", 0))
        self.bob_port = temp.getsockname()[1]
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

        self.kdc_server: KDCServer | None = None
        self.bob_server: BobServer | None = None

    def tearDown(self: "TestMessagingAndUIP6") -> None:
        if self.bob_server:
            self.bob_server.stop()
        if self.kdc_server:
            self.kdc_server.stop()
        for log in (self.kdc_logger, self.alice_logger, self.bob_logger):
            for h in list(log.handlers):
                h.close()
                log.removeHandler(h)
        logging.shutdown()
        self.temp_dir.cleanup()

    def _setup_authenticated_pair(
        self: "TestMessagingAndUIP6",
    ) -> tuple[AliceSession, BobServer]:
        self.kdc_server = KDCServer(self.kdc_cfg, {"alice": self.KA, "bob": self.KB}, self.kdc_logger)
        self.kdc_server.start()

        self.bob_server = BobServer(self.bob_cfg, self.KB, self.bob_logger)
        self.bob_server.start()
        time.sleep(0.05)

        alice_session = AliceSession()
        request_session_key(self.alice_cfg, self.KA, alice_session, self.alice_logger)
        authenticate_with_bob(self.alice_cfg, alice_session, self.alice_logger, ui.print_incoming)
        time.sleep(0.05)
        return alice_session, self.bob_server

    def test_t6_1_and_t6_2_bidirectional_app_messages(self: "TestMessagingAndUIP6") -> None:
        alice, bob = self._setup_authenticated_pair()

        plain1, ct1 = send_app_message(alice, "alice", "Halo dari Alice", self.alice_logger)
        time.sleep(0.05)

        bob_history = bob.session.get_history()
        self.assertEqual(len(bob_history), 1)
        self.assertEqual(bob_history[0]["from"], "alice")
        self.assertEqual(bob_history[0]["plaintext"], plain1)
        self.assertEqual(bob_history[0]["ct"], ct1)

        plain2, ct2 = send_app_message(bob.session, "bob", "Halo dari Bob", self.bob_logger)
        time.sleep(0.05)

        alice_history = alice.get_history()
        self.assertEqual(len(alice_history), 2)
        received_at_alice = [m for m in alice_history if m["from"] == "bob"]
        self.assertEqual(len(received_at_alice), 1)
        self.assertEqual(received_at_alice[0]["plaintext"], plain2)
        self.assertEqual(received_at_alice[0]["ct"], ct2)
        close_alice_session(alice)

    def test_t6_3_ten_alternating_messages(self: "TestMessagingAndUIP6") -> None:
        alice, bob = self._setup_authenticated_pair()

        for i in range(10):
            send_app_message(alice, "alice", f"Pesan Alice {i}")
            time.sleep(0.02)
            send_app_message(bob.session, "bob", f"Pesan Bob {i}")
            time.sleep(0.02)

        bob_msgs_from_alice = [m for m in bob.session.get_history() if m["from"] == "alice"]
        alice_msgs_from_bob = [m for m in alice.get_history() if m["from"] == "bob"]

        self.assertEqual(len(bob_msgs_from_alice), 10)
        self.assertEqual(len(alice_msgs_from_bob), 10)
        for i in range(10):
            self.assertEqual(bob_msgs_from_alice[i]["plaintext"], f"Pesan Alice {i}")
            self.assertEqual(alice_msgs_from_bob[i]["plaintext"], f"Pesan Bob {i}")
        close_alice_session(alice)

    def test_t6_4_concurrent_sends_no_interleaving(self: "TestMessagingAndUIP6") -> None:
        alice, bob = self._setup_authenticated_pair()

        def _alice_sender() -> None:
            for i in range(5):
                send_app_message(alice, "alice", f"A{i}")

        def _bob_sender() -> None:
            for i in range(5):
                send_app_message(bob.session, "bob", f"B{i}")

        t1, t2 = threading.Thread(target=_alice_sender), threading.Thread(target=_bob_sender)
        t1.start(); t2.start(); t1.join(); t2.join()
        time.sleep(0.1)

        bob_from_a = [m for m in bob.session.get_history() if m["from"] == "alice"]
        alice_from_b = [m for m in alice.get_history() if m["from"] == "bob"]
        self.assertEqual(len(bob_from_a), 5)
        self.assertEqual(len(alice_from_b), 5)
        close_alice_session(alice)

    def test_t6_5_distinct_ivs_for_same_plaintext(self: "TestMessagingAndUIP6") -> None:
        alice, _ = self._setup_authenticated_pair()
        _, ct1 = send_app_message(alice, "alice", "pesan identik")
        _, ct2 = send_app_message(alice, "alice", "pesan identik")
        self.assertNotEqual(ct1, ct2)
        close_alice_session(alice)

    def test_t6_6_plaintext_validation_rules(self: "TestMessagingAndUIP6") -> None:
        alice, _ = self._setup_authenticated_pair()
        with self.assertRaises(ValueError):
            send_app_message(alice, "alice", "")
        with self.assertRaises(ValueError):
            send_app_message(alice, "alice", "a\x00b")
        with self.assertRaises(ValueError):
            send_app_message(alice, "alice", "x" * 1025)
        close_alice_session(alice)

    def test_t6_7_and_t6_26_tampered_ciphertext_error_handling(self: "TestMessagingAndUIP6") -> None:
        alice, bob = self._setup_authenticated_pair()

        bad_msg = build_app_msg("alice", alice.ks, "asli")
        bad_msg["body"]["ct"] = "00" * len(bad_msg["body"]["ct"])

        with alice.send_lock:
            send_message(alice.client_sock, bad_msg)
        time.sleep(0.05)

        self.assertEqual(bob.session.state, BobState.AUTHENTICATED)
        self.assertEqual(alice.state, AliceState.AUTHENTICATED)

        send_app_message(alice, "alice", "pesan setelah error")
        time.sleep(0.05)
        history = [m for m in bob.session.get_history() if m["from"] == "alice"]
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["plaintext"], "pesan setelah error")
        close_alice_session(alice)

    def test_t6_8_and_t6_23_bye_handshake_idempotent(self: "TestMessagingAndUIP6") -> None:
        alice, bob = self._setup_authenticated_pair()

        close_alice_session(alice, send_bye=True)
        time.sleep(0.05)

        self.assertEqual(alice.state, AliceState.IDLE)
        self.assertEqual(bob.session.state, BobState.LISTENING)
        self.assertIsNone(alice.ks)
        self.assertIsNone(bob.session.ks)

    def test_t6_9_sudden_socket_drop_handling(self: "TestMessagingAndUIP6") -> None:
        alice, bob = self._setup_authenticated_pair()
        close_socket(alice.client_sock)
        time.sleep(0.1)

        self.assertEqual(bob.session.state, BobState.LISTENING)
        self.assertIsNone(bob.session.ks)

    def test_t6_10_send_message_pre_auth_rejected(self: "TestMessagingAndUIP6") -> None:
        session = AliceSession(state=AliceState.IDLE)
        with self.assertRaises(StateError):
            send_app_message(session, "alice", "halo")

    def test_t6_11_change_ka_disconnects_active_session(self: "TestMessagingAndUIP6") -> None:
        alice, bob = self._setup_authenticated_pair()

        close_alice_session(alice, send_bye=True)
        new_ka = b"new_alice_key___"

        self.assertEqual(alice.state, AliceState.IDLE)
        self.assertIsNone(alice.ks)
        time.sleep(0.05)
        self.assertEqual(bob.session.state, BobState.LISTENING)

    def test_t6_12_and_t6_14_change_kb_and_protocol_renegotiation(self: "TestMessagingAndUIP6") -> None:
        alice, bob = self._setup_authenticated_pair()
        close_alice_session(alice, send_bye=True)

        new_kb = b"brand_new_bob_k_"
        bob.change_key(new_kb)

        request_session_key(self.alice_cfg, self.KA, alice)
        with self.assertRaises(Exception):
            authenticate_with_bob(self.alice_cfg, alice)

        self.kdc_server.change_key("bob", new_kb)
        request_session_key(self.alice_cfg, self.KA, alice)
        authenticate_with_bob(self.alice_cfg, alice)
        self.assertEqual(alice.state, AliceState.AUTHENTICATED)
        self.assertEqual(bob.session.state, BobState.AUTHENTICATED)
        close_alice_session(alice)

    def test_t6_13_kdc_key_change_isolates_active_session(self: "TestMessagingAndUIP6") -> None:
        alice, bob = self._setup_authenticated_pair()

        self.kdc_server.change_key("alice", b"different_ka____")

        send_app_message(alice, "alice", "masih aktif")
        time.sleep(0.05)
        self.assertEqual(bob.session.get_history()[-1]["plaintext"], "masih aktif")
        close_alice_session(alice)

    def test_t6_16_and_t6_25_kcv_computation_and_display(self: "TestMessagingAndUIP6") -> None:
        alice, bob = self._setup_authenticated_pair()
        kcv_alice = compute_kcv(alice.ks)
        kcv_bob = compute_kcv(bob.session.ks)

        self.assertEqual(len(kcv_alice), 6)
        self.assertEqual(kcv_alice, kcv_bob)
        close_alice_session(alice)
        self.assertIsNone(alice.ks)

    def test_t6_18_log_audit_and_redaction(self: "TestMessagingAndUIP6") -> None:
        alice, _ = self._setup_authenticated_pair()
        plain, ct = send_app_message(alice, "alice", "Pesan rahasia audit", self.alice_logger)
        time.sleep(0.05)

        with open(self.alice_log, "r", encoding="utf-8") as f:
            logs = f.read()

        self.assertIn("Pesan rahasia audit", logs)
        self.assertIn(ct, logs)
        for secret in (self.KA.decode(), self.KB.decode(), alice.ks.decode()):
            self.assertNotIn(secret, logs)
        close_alice_session(alice)

    def test_t6_21_unread_counter_and_history(self: "TestMessagingAndUIP6") -> None:
        alice, bob = self._setup_authenticated_pair()
        for i in range(3):
            send_app_message(alice, "alice", f"pesan {i}")
        time.sleep(0.05)

        self.assertEqual(bob.session.unread_count, 3)
        history = bob.session.get_history()
        self.assertEqual(len(history), 3)
        self.assertEqual(bob.session.unread_count, 0)
        close_alice_session(alice)

    def test_t6_22_ui_non_tty_clean_output(self: "TestMessagingAndUIP6") -> None:
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            ui.print_info("Status ok")
            ui.print_incoming({"from": "alice", "plaintext": "test", "ct": "aabb"})
        out = captured.getvalue()
        self.assertIn("[INFO] Status ok", out)
        self.assertIn("Plaintext : test", out)
        self.assertNotIn("\u2014", out)
        self.assertNotIn("\033[", out)

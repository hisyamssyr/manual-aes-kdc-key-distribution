import io
import socket
import sys
import threading
import time
import unittest
from unittest.mock import patch

from network import close_socket, recv_message
from protocol import build_app_msg, build_bye
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
    KS = b"shared_session_k"

    def test_ui_non_tty_printing_and_clean_format(self: "TestMessagingAndUIP6") -> None:
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            ui.print_info("koneksi berhasil")
            ui.print_error("terjadi kesalahan")
            ui.print_incoming({"from": "alice", "plaintext": "halo", "ct": "01020304"})
            ui.render_status("alice", "alice", "bob", "AUTHENTICATED", "a1b2c3", 1, "NONE")

        output = captured.getvalue()
        self.assertIn("[INFO] koneksi berhasil", output)
        self.assertIn("[ERROR] terjadi kesalahan", output)
        self.assertIn("[PESAN MASUK] dari alice:", output)
        self.assertIn("Plaintext : halo", output)
        self.assertIn("Ciphertext: 01020304", output)
        self.assertNotIn("—", output)
        self.assertNotIn("\033[", output)

    def test_ui_prompt_input(self: "TestMessagingAndUIP6") -> None:
        with patch("builtins.input", return_value="pesan uji\r\n"):
            result = ui.prompt_input("Masukkan teks: ")
            self.assertEqual(result, "pesan uji")

    def test_send_app_message_state_guard(self: "TestMessagingAndUIP6") -> None:
        session = AliceSession(state=AliceState.IDLE)
        with self.assertRaises(StateError):
            send_app_message(session, "alice", "halo")

    def test_send_app_message_input_validation(self: "TestMessagingAndUIP6") -> None:
        s1, s2 = socket.socketpair()
        try:
            session = AliceSession(
                state=AliceState.AUTHENTICATED, ks=self.KS, client_sock=s1
            )
            with self.assertRaises(ValueError):
                send_app_message(session, "alice", "")
            with self.assertRaises(ValueError):
                send_app_message(session, "alice", "halo \x00")
            with self.assertRaises(ValueError):
                send_app_message(session, "alice", "a" * 1025)
        finally:
            close_socket(s1)
            close_socket(s2)

    def test_send_and_receive_app_message(self: "TestMessagingAndUIP6") -> None:
        s1, s2 = socket.socketpair()
        try:
            alice = AliceSession(state=AliceState.AUTHENTICATED, ks=self.KS, client_sock=s1)
            bob = BobSession(state=BobState.AUTHENTICATED, ks=self.KS, client_sock=s2)

            received: list[dict[str, str]] = []
            receiver_thread = threading.Thread(
                target=run_session_receiver,
                args=(bob, "alice", received.append, lambda: None),
                daemon=True,
            )
            receiver_thread.start()

            plain, ct = send_app_message(alice, "alice", "Halo Bob!")
            time.sleep(0.05)

            self.assertEqual(len(received), 1)
            self.assertEqual(received[0]["from"], "alice")
            self.assertEqual(received[0]["plaintext"], "Halo Bob!")
            self.assertEqual(received[0]["ct"], ct)
            self.assertEqual(bob.unread_count, 1)

            history = bob.get_history()
            self.assertEqual(len(history), 1)
            self.assertEqual(bob.unread_count, 0)

            bob.close_event.set()
            receiver_thread.join(timeout=1.0)
        finally:
            close_socket(s1)
            close_socket(s2)

    def test_corrupted_ciphertext_sends_decrypt_fail_and_keeps_session(
        self: "TestMessagingAndUIP6",
    ) -> None:
        s1, s2 = socket.socketpair()
        try:
            bob = BobSession(state=BobState.AUTHENTICATED, ks=self.KS, client_sock=s2)
            received: list[dict[str, str]] = []
            receiver_thread = threading.Thread(
                target=run_session_receiver,
                args=(bob, "alice", received.append, lambda: None),
                daemon=True,
            )
            receiver_thread.start()

            corrupted_msg = build_app_msg("alice", self.KS, "asli")
            corrupted_msg["body"]["ct"] = "ff" * len(corrupted_msg["body"]["ct"])

            with bob.send_lock:
                from network import send_message
                send_message(s1, corrupted_msg)

            resp = recv_message(s1, timeout=1.0)
            self.assertEqual(resp.get("type"), "ERROR")
            self.assertEqual(resp.get("code"), "DECRYPT_FAIL")
            self.assertFalse(bob.close_event.is_set())

            bob.close_event.set()
            receiver_thread.join(timeout=1.0)
        finally:
            close_socket(s1)
            close_socket(s2)

    def test_bye_message_terminates_receiver_cleanly(
        self: "TestMessagingAndUIP6",
    ) -> None:
        s1, s2 = socket.socketpair()
        try:
            closed = False

            def _on_close() -> None:
                nonlocal closed
                closed = True

            bob = BobSession(state=BobState.AUTHENTICATED, ks=self.KS, client_sock=s2)
            receiver_thread = threading.Thread(
                target=run_session_receiver,
                args=(bob, "alice", lambda _: None, _on_close),
                daemon=True,
            )
            receiver_thread.start()

            from network import send_message
            send_message(s1, build_bye())
            time.sleep(0.05)

            self.assertTrue(closed)
            self.assertTrue(bob.close_event.is_set())
            receiver_thread.join(timeout=1.0)
        finally:
            close_socket(s1)
            close_socket(s2)

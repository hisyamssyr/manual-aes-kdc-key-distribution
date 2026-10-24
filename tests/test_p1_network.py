import socket
import struct
import threading
import time
import unittest

from network import (
    BadFrame,
    BadHeader,
    BadPayload,
    ConnectionClosed,
    FrameTooLarge,
    MAX_PAYLOAD_SIZE,
    NetworkError,
    NetworkTimeout,
    close_socket,
    connect,
    make_listener,
    recv_message,
    send_message,
)


class NetworkTests(unittest.TestCase):
    def test_loopback_send_and_receive_dict(self) -> None:
        sender, receiver = socket.socketpair()
        try:
            payload = {"v": 1, "type": "TEST", "text": "halo"}
            send_message(sender, payload)
            self.assertEqual(recv_message(receiver, timeout=1.0), payload)
        finally:
            close_socket(sender)
            close_socket(receiver)

    def test_fragmented_frame_is_reassembled(self) -> None:
        sender, receiver = socket.socketpair()
        encoded = b'{"v":1,"type":"TEST","text":"fragmented"}'
        frame = struct.pack("!I", len(encoded)) + encoded
        writer = threading.Thread(target=self._send_one_byte_at_a_time, args=(sender, frame))
        writer.start()
        try:
            self.assertEqual(
                recv_message(receiver, timeout=1.0),
                {"v": 1, "type": "TEST", "text": "fragmented"},
            )
        finally:
            writer.join(timeout=1.0)
            close_socket(sender)
            close_socket(receiver)

    def test_coalesced_frames_are_read_separately(self) -> None:
        sender, receiver = socket.socketpair()
        try:
            first = b'{"number":1}'
            second = b'{"number":2}'
            sender.sendall(
                struct.pack("!I", len(first))
                + first
                + struct.pack("!I", len(second))
                + second
            )
            self.assertEqual(recv_message(receiver, timeout=1.0), {"number": 1})
            self.assertEqual(recv_message(receiver, timeout=1.0), {"number": 2})
        finally:
            close_socket(sender)
            close_socket(receiver)

    def test_invalid_headers_and_payloads_are_rejected(self) -> None:
        non_object_payload = b"[]"
        malformed_payload = b'{"a":1'
        duplicate_key_payload = b'{"a":1,"a":2}'
        cases: list[tuple[bytes, type[Exception]]] = [
            (struct.pack("!I", 0), BadHeader),
            (struct.pack("!I", MAX_PAYLOAD_SIZE + 1), FrameTooLarge),
            (struct.pack("!I", len(non_object_payload)) + non_object_payload, BadPayload),
            (struct.pack("!I", len(malformed_payload)) + malformed_payload, BadPayload),
            (struct.pack("!I", len(duplicate_key_payload)) + duplicate_key_payload, BadPayload),
        ]
        for frame, exception_type in cases:
            with self.subTest(exception_type=exception_type.__name__):
                sender, receiver = socket.socketpair()
                try:
                    sender.sendall(frame)
                    with self.assertRaises(exception_type):
                        recv_message(receiver, timeout=1.0)
                finally:
                    close_socket(sender)
                    close_socket(receiver)

    def test_truncated_frames_and_total_deadline_raise_expected_errors(self) -> None:
        sender, receiver = socket.socketpair()
        try:
            sender.sendall(b"\x00\x00")
            close_socket(sender)
            with self.assertRaises(ConnectionClosed):
                recv_message(receiver, timeout=1.0)
        finally:
            close_socket(receiver)

        sender, receiver = socket.socketpair()
        try:
            sender.sendall(struct.pack("!I", 10) + b"abc")
            started_at = time.monotonic()
            with self.assertRaises(NetworkTimeout):
                recv_message(receiver, timeout=0.05)
            self.assertLess(time.monotonic() - started_at, 0.5)
        finally:
            close_socket(sender)
            close_socket(receiver)

    def test_send_rejects_oversized_payload_before_writing(self) -> None:
        sender, receiver = socket.socketpair()
        try:
            with self.assertRaises(FrameTooLarge):
                send_message(sender, {"blob": "x" * MAX_PAYLOAD_SIZE})
            receiver.settimeout(0.05)
            with self.assertRaises(socket.timeout):
                receiver.recv(1)
        finally:
            close_socket(sender)
            close_socket(receiver)

    def test_connect_failure_and_listener_restart(self) -> None:
        listener = make_listener("127.0.0.1", 0)
        port = listener.getsockname()[1]
        close_socket(listener)

        with self.assertRaises(NetworkError) as captured:
            connect("127.0.0.1", port, 0.2)
        self.assertIn(str(port), str(captured.exception))

        restarted_listener = make_listener("127.0.0.1", port)
        try:
            self.assertEqual(restarted_listener.getsockname()[1], port)
        finally:
            close_socket(restarted_listener)

    def test_non_finite_timeouts_are_rejected(self) -> None:
        for timeout in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    connect("127.0.0.1", 1, timeout)
                sender, receiver = socket.socketpair()
                try:
                    with self.assertRaises(ValueError):
                        recv_message(receiver, timeout=timeout)
                finally:
                    close_socket(sender)
                    close_socket(receiver)

    def test_timeout_none_blocks_despite_existing_socket_timeout(self) -> None:
        sender, receiver = socket.socketpair()
        receiver.settimeout(0.05)
        result: dict[str, object] = {}
        started = threading.Event()

        def receive() -> None:
            started.set()
            try:
                result["message"] = recv_message(receiver, timeout=None)
            except Exception as error:
                result["error"] = error

        reader = threading.Thread(target=receive)
        reader.start()
        try:
            self.assertTrue(started.wait(1.0))
            time.sleep(0.2)
            self.assertTrue(reader.is_alive())
            send_message(sender, {"v": 1, "type": "TEST"})
        finally:
            reader.join(timeout=1.0)
            close_socket(sender)
            close_socket(receiver)

        self.assertNotIn("error", result)
        self.assertEqual(result.get("message"), {"v": 1, "type": "TEST"})

    def test_frame_error_subclasses_preserve_bad_frame_compatibility(self) -> None:
        self.assertTrue(issubclass(BadHeader, BadFrame))
        self.assertTrue(issubclass(BadPayload, BadFrame))

    def _send_one_byte_at_a_time(self, sock: socket.socket, data: bytes) -> None:
        for byte in data:
            sock.sendall(bytes((byte,)))

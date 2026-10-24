import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any

from app_logging import RingBufferHandler, audit_app_message, configure_logging
from config import ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self._directory = Path(self._temporary_directory.name)

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    def test_valid_role_configs_receive_defaults(self) -> None:
        alice_path = self._write_config(
            "alice.json",
            {
                "id": "alice",
                "peer_id": "bob",
                "kdc": {"host": "127.0.0.1"},
                "bob": {"host": "127.0.0.1"},
            },
        )
        bob_path = self._write_config(
            "bob.json",
            {
                "id": "bob",
                "peer_id": "alice",
                "listen": {"host": "0.0.0.0"},
            },
        )
        kdc_path = self._write_config(
            "kdc.json",
            {"listen": {"host": "0.0.0.0"}, "registry_ids": ["alice", "bob"]},
        )

        alice = load_config(alice_path, "alice")
        bob = load_config(bob_path, "bob")
        kdc = load_config(kdc_path, "kdc")

        self.assertEqual(alice["kdc"]["port"], 5000)
        self.assertEqual(alice["bob"]["port"], 5001)
        self.assertEqual(alice["timeouts"], {"connect": 5.0, "step": 10.0})
        self.assertEqual(bob["logging"], {"file": "logs/bob.log", "level": "INFO"})
        self.assertEqual(kdc["logging"], {"file": "logs/kdc.log", "level": "INFO"})

    def test_missing_or_invalid_json_raises_friendly_config_error(self) -> None:
        missing_path = str(self._directory / "missing.json")
        invalid_path = self._directory / "invalid.json"
        invalid_path.write_text("{", encoding="utf-8")

        for path in (missing_path, str(invalid_path)):
            with self.subTest(path=path):
                with self.assertRaises(ConfigError):
                    load_config(path, "alice")

    def test_invalid_required_values_are_rejected(self) -> None:
        valid_config = {
            "id": "alice",
            "peer_id": "bob",
            "kdc": {"host": "127.0.0.1", "port": 5000},
            "bob": {"host": "127.0.0.1", "port": 5001},
        }
        invalid_configs = [
            {key: value for key, value in valid_config.items() if key != "id"},
            {**valid_config, "kdc": {"host": "127.0.0.1", "port": True}},
            {**valid_config, "timeouts": {"step": 10}},
            {**valid_config, "logging": {"level": "TRACE"}},
            {**valid_config, "Ka": "not-permitted"},
        ]

        for index, config in enumerate(invalid_configs):
            with self.subTest(config=index):
                path = self._write_config(f"invalid-{index}.json", config)
                with self.assertRaises(ConfigError):
                    load_config(path, "alice")

    def test_unknown_fields_are_ignored_with_a_warning(self) -> None:
        path = self._write_config(
            "unknown.json",
            {
                "id": "alice",
                "peer_id": "bob",
                "kdc": {"host": "127.0.0.1", "unused": "value"},
                "bob": {"host": "127.0.0.1"},
                "unused": "value",
            },
        )

        with self.assertLogs("config", level="WARNING") as captured:
            loaded = load_config(path, "alice")

        self.assertNotIn("unused", loaded)
        self.assertEqual(len(captured.output), 2)

    def test_logging_uses_private_append_only_one_line_file(self) -> None:
        log_path = self._directory / "logs" / "alice.log"
        logger = configure_logging("alice", str(log_path), "INFO")
        audit_app_message(logger, "in", "bob", "hello\nworld", "A1B2")
        for handler in logger.handlers:
            handler.flush()

        content = log_path.read_text(encoding="utf-8")
        permission = stat.S_IMODE(os.stat(log_path).st_mode)

        self.assertEqual(permission, 0o600)
        self.assertEqual(len(content.splitlines()), 1)
        self.assertIn('event="APP_MSG"', content)
        self.assertIn('ct="a1b2"', content)
        self.assertIn('plaintext="hello\\nworld"', content)

    def test_ring_buffer_keeps_only_the_latest_events(self) -> None:
        handler = RingBufferHandler(capacity=2)
        logger = configure_logging("kdc", str(self._directory / "kdc.log"), "INFO")
        logger.addHandler(handler)
        logger.info("first", extra={"event": "ONE"})
        logger.info("second", extra={"event": "TWO"})
        logger.info("third", extra={"event": "THREE"})

        self.assertEqual(len(handler.records), 2)
        self.assertIn("TWO", handler.records[0])
        self.assertIn("THREE", handler.records[1])

    def _write_config(self, filename: str, contents: dict[str, Any]) -> str:
        path = self._directory / filename
        path.write_text(json.dumps(contents), encoding="utf-8")
        return str(path)

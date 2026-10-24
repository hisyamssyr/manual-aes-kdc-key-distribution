import json
import logging
import os
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


APP_MESSAGE_EVENT = "APP_MSG"
CONFIG_LOGGER_NAME = "config"
CONFIG_WARNING_EVENT = "CONFIG_WARNING"
DEFAULT_LOG_DIRECTORY = "logs"
MAX_RING_BUFFER_EVENTS = 20
STANDARD_RECORD_FIELDS = frozenset(logging.makeLogRecord({}).__dict__)
FORBIDDEN_LOG_FIELDS = frozenset(
    {"ka", "kb", "ks", "key", "kcv", "n1", "n2", "nonce"}
)
NON_AUDIT_SENSITIVE_FIELDS = frozenset(
    {"plaintext", "ct", "ciphertext", "ticket", "body", "iv"}
)


class RingBufferHandler(logging.Handler):
    def __init__(self: "RingBufferHandler", capacity: int = MAX_RING_BUFFER_EVENTS) -> None:
        super().__init__()
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ValueError("capacity must be a positive integer")
        self._records: deque[str] = deque(maxlen=min(capacity, MAX_RING_BUFFER_EVENTS))
        self._records_lock = threading.Lock()

    @property
    def records(self: "RingBufferHandler") -> list[str]:
        with self._records_lock:
            return list(self._records)

    def emit(self: "RingBufferHandler", record: logging.LogRecord) -> None:
        try:
            event = getattr(record, "event", "LOG")
            entry = f"{record.levelname} {event} {record.getMessage()}"
            with self._records_lock:
                self._records.append(entry)
        except Exception:
            self.handleError(record)


class ConfigWarningCapture(logging.Handler):
    def __init__(
        self: "ConfigWarningCapture", logger: logging.Logger
    ) -> None:
        super().__init__(level=logging.WARNING)
        self._logger = logger
        self._records: list[logging.LogRecord] = []
        self._records_lock = threading.Lock()

    def emit(self: "ConfigWarningCapture", record: logging.LogRecord) -> None:
        with self._records_lock:
            self._records.append(record)

    def drain(self: "ConfigWarningCapture") -> list[logging.LogRecord]:
        with self._records_lock:
            records = list(self._records)
            self._records.clear()
        return records

    def detach(self: "ConfigWarningCapture") -> None:
        self._logger.removeHandler(self)
        self.close()


def configure_logging(role: str, log_file: str | None, level: str) -> logging.Logger:
    if not isinstance(role, str) or not role:
        raise ValueError("role harus berupa string tidak kosong")
    if not isinstance(level, str) or level not in logging._nameToLevel:
        raise ValueError("level logging tidak valid")
    if log_file is not None and (not isinstance(log_file, str) or not log_file):
        raise ValueError("path log tidak valid")

    if log_file is None:
        target_path = Path(DEFAULT_LOG_DIRECTORY) / f"{role}.log"
    else:
        target_path = Path(log_file)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(f"manual_aes_kdc.{role}")
    logger.setLevel(logging._nameToLevel[level])
    logger.propagate = False
    _remove_existing_handlers(logger)

    handler = logging.FileHandler(target_path, mode="a", encoding="utf-8")
    os.chmod(target_path, 0o600)
    handler.setLevel(logging._nameToLevel[level])
    handler.setFormatter(_EventFormatter(role))
    logger.addHandler(handler)
    return logger


def capture_config_warnings(
    logger_name: str = CONFIG_LOGGER_NAME,
) -> ConfigWarningCapture:
    if not isinstance(logger_name, str) or not logger_name:
        raise ValueError("nama logger config tidak valid")
    logger = logging.getLogger(logger_name)
    handler = ConfigWarningCapture(logger)
    logger.addHandler(handler)
    return handler


def flush_config_warnings(
    handler: ConfigWarningCapture, logger: logging.Logger
) -> None:
    if not isinstance(handler, ConfigWarningCapture):
        raise TypeError("handler harus ConfigWarningCapture")
    if not isinstance(logger, logging.Logger):
        raise TypeError("logger harus logging.Logger")
    try:
        for record in handler.drain():
            logger.warning(
                record.getMessage(),
                extra={"event": CONFIG_WARNING_EVENT},
            )
    finally:
        handler.detach()


def audit_app_message(
    logger: logging.Logger,
    direction: str,
    from_id: str,
    plaintext: str,
    ct_hex: str,
) -> None:
    logger.info(
        "application message",
        extra={
            "event": APP_MESSAGE_EVENT,
            "direction": direction,
            "from_id": from_id,
            "plaintext": plaintext,
            "ct": ct_hex.lower(),
        },
    )


class _EventFormatter(logging.Formatter):
    def __init__(self: "_EventFormatter", role: str) -> None:
        super().__init__()
        self._role = role

    def format(self: "_EventFormatter", record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, timezone.utc).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
        event = str(getattr(record, "event", "LOG"))
        fields = {
            field_name: value
            for field_name, value in record.__dict__.items()
            if field_name not in STANDARD_RECORD_FIELDS
            and field_name != "event"
            and field_name.lower() not in FORBIDDEN_LOG_FIELDS
        }
        if event != APP_MESSAGE_EVENT:
            fields = {
                field_name: value
                for field_name, value in fields.items()
                if field_name.lower() not in NON_AUDIT_SENSITIVE_FIELDS
            }
        parts = [
            f"timestamp={timestamp}",
            f"level={record.levelname}",
            f"role={_quote(self._role)}",
            f"event={_quote(event)}",
            f"msg={_quote(record.getMessage())}",
        ]
        parts.extend(
            f"{field_name}={_quote(value)}" for field_name, value in sorted(fields.items())
        )
        return " ".join(parts)


def _remove_existing_handlers(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()


def _quote(value: Any) -> str:
    return json.dumps(str(value), ensure_ascii=True)

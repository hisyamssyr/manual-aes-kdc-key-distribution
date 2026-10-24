import json
import logging
from typing import Any

from encoding_utils import validate_id


DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_KDC_PORT = 5000
DEFAULT_BOB_PORT = 5001
DEFAULT_STEP_TIMEOUT = 10.0
DEFAULT_LOG_LEVEL = "INFO"
LOGGER = logging.getLogger(__name__)
ROLES = frozenset({"alice", "bob", "kdc"})
LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR"})
FORBIDDEN_KEY_FIELDS = frozenset({"ka", "kb", "ks"})


class ConfigError(Exception):
    pass


def load_config(path: str, role: str) -> dict[str, Any]:
    if not isinstance(role, str) or role not in ROLES:
        raise ConfigError("peran konfigurasi tidak dikenal")
    raw_config = _read_json_object(path)
    _reject_secret_fields(raw_config)
    _warn_unknown_fields(raw_config, _allowed_top_level_fields(role), "")

    if role == "alice":
        return _load_alice_config(raw_config)
    if role == "bob":
        return _load_bob_config(raw_config)
    return _load_kdc_config(raw_config)


def _read_json_object(path: str) -> dict[str, Any]:
    if not isinstance(path, str) or not path:
        raise ConfigError("path konfigurasi tidak valid")
    try:
        with open(path, "r", encoding="utf-8") as config_file:
            parsed_config = json.load(config_file)
    except FileNotFoundError as error:
        raise ConfigError("berkas konfigurasi tidak ditemukan") from error
    except PermissionError as error:
        raise ConfigError("berkas konfigurasi tidak dapat dibaca") from error
    except OSError as error:
        raise ConfigError("berkas konfigurasi tidak dapat dibuka") from error
    except json.JSONDecodeError as error:
        raise ConfigError("format JSON konfigurasi tidak valid") from error

    if not isinstance(parsed_config, dict):
        raise ConfigError("konfigurasi harus berupa objek JSON")
    return parsed_config


def _load_alice_config(raw_config: dict[str, Any]) -> dict[str, Any]:
    identity = _require_id(raw_config, "id")
    peer_id = _require_id(raw_config, "peer_id")
    kdc = _load_endpoint(raw_config, "kdc", DEFAULT_KDC_PORT)
    bob = _load_endpoint(raw_config, "bob", DEFAULT_BOB_PORT)
    timeouts = _load_timeouts(raw_config)
    logging_config = _load_logging(raw_config, identity)
    return {
        "id": identity,
        "peer_id": peer_id,
        "kdc": kdc,
        "bob": bob,
        "timeouts": timeouts,
        "logging": logging_config,
    }


def _load_bob_config(raw_config: dict[str, Any]) -> dict[str, Any]:
    identity = _require_id(raw_config, "id")
    peer_id = _require_id(raw_config, "peer_id")
    listener = _load_endpoint(raw_config, "listen", DEFAULT_BOB_PORT)
    timeouts = _load_timeouts(raw_config)
    logging_config = _load_logging(raw_config, identity)
    return {
        "id": identity,
        "peer_id": peer_id,
        "listen": listener,
        "timeouts": timeouts,
        "logging": logging_config,
    }


def _load_kdc_config(raw_config: dict[str, Any]) -> dict[str, Any]:
    listener = _load_endpoint(raw_config, "listen", DEFAULT_KDC_PORT)
    registry_ids = _load_registry_ids(raw_config)
    timeouts = _load_timeouts(raw_config)
    logging_config = _load_logging(raw_config, "kdc")
    return {
        "listen": listener,
        "registry_ids": registry_ids,
        "timeouts": timeouts,
        "logging": logging_config,
    }


def _allowed_top_level_fields(role: str) -> frozenset[str]:
    common_fields = frozenset({"timeouts", "logging"})
    if role == "alice":
        return common_fields | frozenset({"id", "peer_id", "kdc", "bob"})
    if role == "bob":
        return common_fields | frozenset({"id", "peer_id", "listen"})
    return common_fields | frozenset({"listen", "registry_ids"})


def _reject_secret_fields(value: Any) -> None:
    if isinstance(value, dict):
        for field_name, field_value in value.items():
            if isinstance(field_name, str) and field_name.lower() in FORBIDDEN_KEY_FIELDS:
                raise ConfigError("konfigurasi tidak boleh memuat field key")
            _reject_secret_fields(field_value)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_fields(item)


def _warn_unknown_fields(
    value: dict[str, Any], allowed_fields: frozenset[str], location: str
) -> None:
    for field_name in value:
        if field_name not in allowed_fields:
            field_path = f"{location}.{field_name}" if location else field_name
            LOGGER.warning("ignoring unknown configuration field: %s", field_path)


def _require_id(raw_config: dict[str, Any], field_name: str) -> str:
    if field_name not in raw_config:
        raise ConfigError(f"field wajib '{field_name}' tidak ada")
    try:
        return validate_id(raw_config[field_name])
    except ValueError as error:
        raise ConfigError(f"field '{field_name}' tidak valid") from error


def _load_endpoint(
    raw_config: dict[str, Any], field_name: str, default_port: int
) -> dict[str, Any]:
    if field_name not in raw_config:
        raise ConfigError(f"field wajib '{field_name}' tidak ada")
    endpoint = raw_config[field_name]
    if not isinstance(endpoint, dict):
        raise ConfigError(f"field '{field_name}' harus berupa objek")
    _warn_unknown_fields(endpoint, frozenset({"host", "port"}), field_name)

    host = endpoint.get("host")
    if not isinstance(host, str) or not host.strip():
        raise ConfigError(f"host untuk '{field_name}' tidak valid")
    port = endpoint.get("port", default_port)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ConfigError(f"port untuk '{field_name}' harus 1 sampai 65535")
    return {"host": host, "port": port}


def _load_timeouts(raw_config: dict[str, Any]) -> dict[str, float]:
    timeouts = raw_config.get("timeouts", {})
    if not isinstance(timeouts, dict):
        raise ConfigError("field 'timeouts' harus berupa objek")
    _warn_unknown_fields(timeouts, frozenset({"connect", "step"}), "timeouts")
    connect_timeout = _validate_timeout(
        timeouts.get("connect", DEFAULT_CONNECT_TIMEOUT), "timeouts.connect"
    )
    step_timeout = _validate_timeout(timeouts.get("step", DEFAULT_STEP_TIMEOUT), "timeouts.step")
    return {"connect": connect_timeout, "step": step_timeout}


def _validate_timeout(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, float) or value <= 0:
        raise ConfigError(f"field '{field_name}' harus float lebih besar dari nol")
    return value


def _load_logging(raw_config: dict[str, Any], identity: str) -> dict[str, str]:
    logging_config = raw_config.get("logging", {})
    if not isinstance(logging_config, dict):
        raise ConfigError("field 'logging' harus berupa objek")
    _warn_unknown_fields(logging_config, frozenset({"file", "level"}), "logging")
    log_file = logging_config.get("file", f"logs/{identity}.log")
    level = logging_config.get("level", DEFAULT_LOG_LEVEL)
    if not isinstance(log_file, str) or not log_file:
        raise ConfigError("field 'logging.file' harus berupa string tidak kosong")
    if not isinstance(level, str) or level not in LOG_LEVELS:
        raise ConfigError("field 'logging.level' tidak valid")
    return {"file": log_file, "level": level}


def _load_registry_ids(raw_config: dict[str, Any]) -> list[str]:
    if "registry_ids" not in raw_config:
        raise ConfigError("field wajib 'registry_ids' tidak ada")
    registry_ids = raw_config["registry_ids"]
    if not isinstance(registry_ids, list) or not registry_ids:
        raise ConfigError("field 'registry_ids' harus berupa daftar tidak kosong")

    validated_ids: list[str] = []
    for registry_id in registry_ids:
        try:
            validated_ids.append(validate_id(registry_id))
        except ValueError as error:
            raise ConfigError("field 'registry_ids' memuat id tidak valid") from error
    if len(validated_ids) != len(set(validated_ids)):
        raise ConfigError("field 'registry_ids' tidak boleh duplikat")
    return validated_ids

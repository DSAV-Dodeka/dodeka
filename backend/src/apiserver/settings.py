import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from apiserver.resources import res_path

__all__ = ["Settings", "settings"]


@dataclass
class AdminKey:
    key: str
    # Unix timestamp for when it expires
    expiration: int


@dataclass(frozen=True, slots=True, kw_only=True)
class Settings:
    """Application settings loaded from TOML configuration file."""

    db_file: Path = Path("./db.sqlite")
    environment: Literal["test"] | Literal["production"] = "production"
    auth_server_url: str = "http://localhost:3777"
    frontend_origin: str = "https://dsavdodeka.nl"
    debug_logs: bool = False
    private_route_access_file: Path = Path("./private_route.key")
    code_socket_path: Path = Path("/home/tipcl-pop/files/gitp/tiauth-faroe/tokens.sock")
    admin_key: AdminKey | None = None


def find_config_file() -> Path | None:
    """
    Searches in order:
    1. config.toml in resources folder
    2. devenv.toml.local
    3. devenv.toml
    """
    candidates = [
        res_path.joinpath("config.toml"),
        Path("./devenv.toml.local"),
        Path("./devenv.toml"),
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None


def validate_path(name: str, value: object) -> Path:
    """Validate and convert a path setting."""
    if not isinstance(value, str):
        raise ValueError(
            f"Setting '{name}' must be a string, got {type(value).__name__}"
        )
    return Path(value)


def validate_str(name: str, value: object) -> str:
    """Validate a string setting."""
    if not isinstance(value, str):
        raise ValueError(
            f"Setting '{name}' must be a string, got {type(value).__name__}"
        )
    return value


def validate_bool(name: str, value: object) -> bool:
    """Validate a boolean setting."""
    if not isinstance(value, bool):
        raise ValueError(
            f"Setting '{name}' must be a boolean, got {type(value).__name__}"
        )
    return value


def validate_int(name: str, value: object) -> int:
    """Validate an integer setting."""
    if not isinstance(value, int):
        raise ValueError(f"Setting '{name}' must be an int, got {type(value).__name__}")
    return value


def validate_environment(name: str, value: object) -> Literal["test", "production"]:
    """Validate environment setting."""
    env = validate_str(name, value)
    if env not in ("test", "production"):
        raise ValueError(
            f"Setting '{name}' must be 'test' or 'production', got '{env}'"
        )
    return env  # type: ignore


def validate_admin_key(name: str, value: object) -> AdminKey:
    """Validate admin_key setting."""
    if not isinstance(value, dict):
        raise ValueError(
            f"Setting '{name}' must be a table/dict, got {type(value).__name__}"
        )

    key = validate_str(f"{name}.key", value.get("key"))
    expiration = validate_int(f"{name}.expiration", value.get("expiration"))

    return AdminKey(key=key, expiration=expiration)


def load_settings() -> Settings:
    config_file = find_config_file()

    # Start with empty config
    config = {}

    # Load and validate TOML config if found
    if config_file is not None:
        with open(config_file, "rb") as f:
            toml_data = tomllib.load(f)

        # Validate and convert each setting
        k = "db_file"
        if k in toml_data:
            config[k] = validate_path(k, toml_data[k])

        k = "environment"
        if k in toml_data:
            config[k] = validate_environment(k, toml_data[k])

        k = "auth_server_url"
        if k in toml_data:
            config[k] = validate_str(k, toml_data[k])

        k = "frontend_origin"
        if k in toml_data:
            config[k] = validate_str(k, toml_data[k])

        k = "debug_logs"
        if k in toml_data:
            config[k] = validate_bool(k, toml_data[k])

        k = "private_route_access_file"
        if k in toml_data:
            config[k] = validate_path(k, toml_data[k])

        k = "code_socket_path"
        if k in toml_data:
            config[k] = validate_path(k, toml_data[k])

        k = "admin_key"
        if k in toml_data:
            config[k] = validate_admin_key(k, toml_data[k])

    return Settings(**config)


# Global settings instance
settings = load_settings()

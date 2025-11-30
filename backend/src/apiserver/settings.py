import tomllib
from dataclasses import dataclass
from pathlib import Path

from apiserver.resources import res_path

__all__ = ["Settings", "settings"]


@dataclass(frozen=True, slots=True, kw_only=True)
class Settings:
    """Application settings loaded from TOML configuration file."""

    db_file: Path = Path("./db.sqlite")
    auth_server_url: str = "http://localhost:3777"
    frontend_origin: str = "https://dsavdodeka.nl"
    debug_logs: bool = False


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


def load_settings() -> Settings:
    config_file = find_config_file()

    # Start with empty config
    config = {}

    # Load and validate TOML config if found
    if config_file is not None:
        with open(config_file, "rb") as f:
            toml_data = tomllib.load(f)

        # Validate and convert each setting
        if "db_file" in toml_data:
            config["db_file"] = validate_path("db_file", toml_data["db_file"])

        if "auth_server_url" in toml_data:
            config["auth_server_url"] = validate_str(
                "auth_server_url", toml_data["auth_server_url"]
            )

        if "frontend_origin" in toml_data:
            config["frontend_origin"] = validate_str(
                "frontend_origin", toml_data["frontend_origin"]
            )

        if "debug_logs" in toml_data:
            config["debug_logs"] = validate_bool("debug_logs", toml_data["debug_logs"])

    return Settings(**config)


# Global settings instance
settings = load_settings()

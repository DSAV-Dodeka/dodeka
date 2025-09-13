from pathlib import Path
from pydantic import BaseModel, FilePath
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["settings", "Settings"]


# https://docs.pydantic.dev/latest/concepts/pydantic_settings
class Settings(BaseSettings):
    model_config = SettingsConfigDict()

    db_file: Path = Path("./db.sqlite")

    # APISERVER_ENV: str

    # # All 'envless' PASSWORDS MUST BE DUMMY

    # # 'envless' MUST BE DUMMY
    # # RECOMMENDED TO LOAD AS ENVIRON
    # KEY_PASS: str

    # MAIL_ENABLED: bool

    # # 'envless' MUST BE DUMMY
    # # RECOMMENDED TO LOAD AS ENVIRON
    # MAIL_PASS: str

    # SMTP_SERVER: str
    # SMTP_PORT: int

    # RECREATE: str = "no"

    # DB_NAME_ADMIN: str


# def get_config_path(config_path_name: Optional[os.PathLike[Any]] = None) -> Path:
#     """Gets path to load onfig from. Environment variable APISERVER_CONFIG takes precedence.

#     Args:
#         config_path_name: Optional path to load config from. If neither env var or argument is given, it will first
#         look for:
#             - env.toml in `resources` (empty by default)
#             - devenv.toml.local in the project path
#             - devenv.toml in the project path
#     Returns:
#         Path for config to load."""
#     env_config_path = os.environ.get("APISERVER_CONFIG")
#     if env_config_path is not None:
#         return Path(env_config_path)
#     elif config_path_name is not None:
#         return Path(config_path_name)

#     try_paths = [
#         res_path.joinpath("env.toml"),
#         project_path.joinpath("devenv.toml.local"),
#         project_path.joinpath("devenv.toml"),
#     ]

#     for path in try_paths:
#         if path.exists():
#             return path

#     raise AppEnvironmentError(
#         "No env.toml found! If you are in development, did you remove `devenv.toml`? If"
#         " you are in production, was `env.toml` not added to resources?"
#     )


# def load_config_with_message(
#     config_path_name: Optional[os.PathLike[Any]] = None,
# ) -> tuple[Config, str]:
#     """Loads and validates config using `get_config_path`. It overrides values in the config with
#     environment variables.

#     Raises:
#         AppEnvironmentError: If failed to validate config."""
#     config_path = get_config_path(config_path_name)

#     with open(config_path, "rb") as f:
#         config = tomllib.load(f)

#     keys_in_environ = set(config.keys()).intersection(os.environ.keys())
#     override_message = (
#         f" with overriding environment variables: {keys_in_environ}"
#         if keys_in_environ
#         else ""
#     )

#     config |= os.environ  # override loaded values with environment variables

#     config_message = f"config from {config_path}{override_message}"

#     try:
#         return Config.model_validate(config), config_message
#     except ValidationError as e:
#         err = ""
#         for err_detail in e.errors():
#             err_ctx = f". context: {err_detail['ctx']}" if "ctx" in err_detail else ""
#             err += (
#                 f"\n\t- Err: {err_detail['loc']} with type={err_detail['type']}:"
#                 f" {err_detail['msg']}{err_ctx}"
#             )

#         raise AppEnvironmentError(
#             f"<magenta>Failed to load {config_message}:{err}</magenta>"
#         )


# def load_config(config_path_name: Optional[os.PathLike[Any]] = None) -> Config:
#     config, _ = load_config_with_message(config_path_name)

#     return config


def define_settings():
    return Settings()


settings = define_settings()

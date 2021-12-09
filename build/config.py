import confspawn.spawn as spwn

from pathlib import Path


def print_config_var(env, var_key):
    cf_path = Path("config.toml")
    spwn.print_env_var(cf_path, env, var_key)

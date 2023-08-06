from typing import Optional

import os
from pathlib import Path
import tomli

from pydantic import BaseModel


# Different scenarios:
# 1) Production ('production'): Every config value is loaded either from config files included in the Docker build or at
# runtime as environment variables (env.py), either set pre-deployment or set at deployment. In this case it can load in
# secrets.
# 2) Testing environment ('test'): Fully featured, automated testing environment in CI. Here it will not affect any
# deployment but can still test against as a live system. It can load in certain secrets, like e-mail passwords. Uses a
# dedicated config file for env.py.
# 3) Local (dev) environment ('localdev'): Can be set up fully featured. No automatic loading of secrets, but can be set
# locally. These secrets MUST NEVER be stored in Git. Use localenv.toml for this. Some tests with live side effects can
# be run.
# 4) No environment ('envless'): Can be in tests either locally or in automated CI, but not in a live environment. No
# access to any secrets and only dummy values from env.py. It does use define.py.


# See below for appropriate values for specific environments
class Config(BaseModel):
    KV_HOST: str
    KV_PORT: int
    # 'envless' MUST BE DUMMY
    # RECOMMENDED TO LOAD AS ENVIRON
    KV_PASS: str


def load_config(config_path_name: Optional[os.PathLike] = None) -> Config:
    config_path = Path(config_path_name)

    with open(config_path, "rb") as f:
        config = tomli.load(f)

    # Config will contain all variables in a dict
    config |= os.environ  # override loaded values with environment variables

    return Config.model_validate(config)

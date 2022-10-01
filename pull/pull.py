import getpass
from pathlib import Path
import shutil


def env():
    env_str = input("Environment: ")

    print(env_str)


def passphrase():
    pw = getpass.getpass("Passphrase for deployment: ")

    print(pw)


def move(time: str, env: str):
    # Move deploy target to env folder for history
    use_src_path = Path(f"./use/{env}")
    deploy_target_path = Path(f"./deployments/{env}/deploy{time}")
    deploy_target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(use_src_path, deploy_target_path)
    # Move deploy target to active
    target_path = Path(f"./deployments/active{env}")
    shutil.copytree(use_src_path, target_path)
    # Move secrets into active
    secr_src_path = Path(f"./deployments/{env}/secrets{time}")
    shutil.move(secr_src_path, target_path)

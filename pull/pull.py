import getpass
from pathlib import Path
import shutil


def passphrase():
    pw = getpass.getpass("Passphrase for deployment: ")

    print(pw)


def move(time: str, env_str: str):
    # Move deploy target to env folder for history
    print("Moving deployment scripts...")
    use_src_path = Path(f"./use/{env_str}")
    deploy_target_path = Path(f"./deployments/{env_str}/deploy{time}")
    deploy_target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(use_src_path, deploy_target_path)
    # Move deploy target to active
    target_path = Path(f"./deployments/active{env_str}")
    if target_path.exists():
        shutil.rmtree(target_path)
    shutil.copytree(use_src_path, target_path)
    # Move secrets into active
    print("Moving secrets...")
    secr_src_path = Path(f"./deployments/{env_str}/secrets{time}")
    secr_target_path = target_path.joinpath("secrets")
    shutil.copytree(secr_src_path, secr_target_path)

def move_backup(time: str, env_str: str):
    # Move deploy target to env folder for history
    print("Moving deployment scripts...")
    use_src_path = Path(f"./use/backup/{env_str}")
    deploy_target_path = Path(f"./deployments/{env_str}/backupdeploy{time}")
    deploy_target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(use_src_path, deploy_target_path)
    # Move deploy target to active
    target_path = Path(f"./deployments/activebackup{env_str}")
    if target_path.exists():
        shutil.rmtree(target_path)
    shutil.copytree(use_src_path, target_path)

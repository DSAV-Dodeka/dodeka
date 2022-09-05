from pathlib import Path
from confspawn.cli import spawn_write

cf_pth = Path('config.toml')
t_path = Path('./db')
tt_path = Path('../cool')

spawn_write(cf_pth, t_path, tt_path, recurse=True)
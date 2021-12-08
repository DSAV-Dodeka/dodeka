from confspawn.spawn import spawn_write


def spawn_build(build_target='configged'):
    print("Building build configuration...")
    spawn_write('./config.toml', './db', target_dir=build_target, source_env='default.db')


def spawn_deploy():
    print("Building DB deploy configuration...")
    spawn_write('./config.toml', './db/deploy', target_dir="../deploydb", join_target=False, source_env='default.db')


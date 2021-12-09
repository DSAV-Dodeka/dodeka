from confspawn.spawn import spawn_write


def spawn_dev():
    print("Building dev configuration...")
    # This one has to go first since target is deleted before write
    spawn_write('./config.toml', './dev', target_dir="../dev", join_target=False, source_env='default.dev')
    spawn_write('./config.toml', './kv/deploy', target_dir="../use/dev/deploykv", join_target=False,
                source_env='default.kv')
    spawn_write('./config.toml', './db/deploy', target_dir="../use/dev/deploydb", join_target=False,
                source_env='default.db')


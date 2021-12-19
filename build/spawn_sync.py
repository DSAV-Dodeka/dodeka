from confspawn.spawn import spawn_write


def spawn_test_sync():
    print("Building test database sync configuration...")
    # This one has to go first since target is deleted before write
    spawn_write('./config.toml', './test_sync', target_dir="../data", join_target=False,
                source_env='default.dev')
    spawn_write('./config.toml', './test_sync/backups', target_dir="../data/backups", join_target=False,
                source_env='default.db')
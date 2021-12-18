from confspawn.spawn import spawn_write


def spawn_backend():
    print("Building backend dev configuration...")
    # This one has to go first since target is deleted before write
    spawn_write('./config.toml', './backend', target_dir="../use/backend/dev", join_target=False,
                source_env='default.dev')
    spawn_write('./config.toml', './backend/kv', target_dir="../use/backend/db", join_target=False,
                source_env='default.kv')
    spawn_write('./config.toml', './backend/kv', target_dir="../use/backend/kv", join_target=False,
                source_env='default.db')

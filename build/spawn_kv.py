from confspawn.spawn import spawn_write


def spawn_librejson(build_target='configged'):
    print("Building librejson build configuration...")
    spawn_write('./config.toml', './kv/librejson', target_dir=build_target, source_env='default.kv')


def spawn_deploy():
    print("Building KV deploy configuration...")
    spawn_write('./config.toml', './kv/deploy', target_dir="../deploykv", join_target=False, source_env='default.kv')

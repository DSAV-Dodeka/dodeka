from confspawn.spawn import spawn_write


def spawn_librejson(build_target='configged'):
    print("Building librejson build configuration...")
    spawn_write('./config.toml', './kv/librejson', target_dir=build_target, source_env='default.kv')
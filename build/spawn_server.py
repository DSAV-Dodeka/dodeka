from confspawn.spawn import spawn_write


def spawn_build(build_target='configged'):
    print("Building server build configuration...")
    spawn_write('./config.toml', './server', target_dir=build_target, source_env='default.server')


def spawn_server():
    print("Building server configuration...")
    # This one has to go first since target is deleted before write
    spawn_write('./config.toml', './server/deploy', target_dir="../use/deployserver", join_target=False,
                source_env='default.server')

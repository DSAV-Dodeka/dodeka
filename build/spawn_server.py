from confspawn.spawn import spawn_write


def spawn_server():
    print("Building server configuration...")
    # This one has to go first since target is deleted before write
    spawn_write('./config.toml', './server/deploy', target_dir="../use/deployserver", join_target=False,
                source_env='default.server')

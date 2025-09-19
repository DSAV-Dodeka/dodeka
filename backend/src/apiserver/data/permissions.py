
def parse_permissions(timestamp: int, permissions: str) -> dict[str, int]:
    perms_split = permissions.split(' ')
    perms_dict: dict[str, int] = {}
    for perm in perms_split:
        spl = perm.split(':')
        if len(spl) != 2:
            continue
        perm_name = spl[0]
        try:
            perm_expiration = int(spl[1])
        except ValueError:
            continue

        if perm_expiration < timestamp:
            continue

        perms_dict[perm_name] = perm_expiration

    return perms_dict

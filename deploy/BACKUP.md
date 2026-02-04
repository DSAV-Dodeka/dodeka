# Dodeka Database Backup & Restore

These scripts use [Restic](https://restic.net/) for incremental, encrypted backups. Restic deduplicates data across snapshots, so hourly backups are storage-efficient. Each backup is compressed with zstd before being stored.

## Setup

### Install restic

```bash
curl -L https://github.com/restic/restic/releases/download/v0.18.1/restic_0.18.1_linux_amd64.bz2 | bunzip2 > /home/backend/.local/bin/restic
chmod +x /home/backend/.local/bin/restic
```

### Initialize repository

```bash
echo "your-secure-password-here" > /mnt/backup/.restic-password
chmod 600 /mnt/backup/.restic-password
restic init --repo /mnt/backup/restic --password-file /mnt/backup/.restic-password
```

### Install scripts

Copy scripts to `/home/backend/.local/bin/`:

```bash
cp dodeka-db-*.sh /home/backend/.local/bin/
chmod +x /home/backend/.local/bin/dodeka-db-*.sh
```

## Usage

### Manual backup

```bash
dodeka-db-backup.sh demo
dodeka-db-backup.sh production
```

### Restore

```bash
# Restore from same environment
dodeka-db-restore.sh demo
dodeka-db-restore.sh production

# Cross-environment restore (clone production to demo)
dodeka-db-restore.sh demo --from production
```

The restore script will:
1. List available snapshots
2. Prompt for snapshot ID (or 'latest')
3. Stop the service
4. Backup current state (tagged `pre-restore`)
5. Restore the selected snapshot
6. Start the service

### Scheduled backup (cron)

The cron script backs up and prunes old snapshots. Defaults to production.

```bash
dodeka-db-cron.sh              # production (default)
dodeka-db-cron.sh production   # explicit
```

Add to crontab for hourly backups:

```bash
crontab -e
```

```
12 * * * * /home/backend/.local/bin/dodeka-db-cron.sh >> /var/log/dodeka-backup.log 2>&1
```

Retention policy:
- 10 latest snapshots
- 24 hourly
- 7 daily
- 4 weekly
- 6 monthly

## Database paths

| Environment | Database path |
|-------------|---------------|
| demo | `/home/backend/dodeka/backend/envs/demo/db.sqlite` |
| production | `/home/backend/dodeka/backend/envs/production/db.sqlite` |

## Snapshot tags

Each backup is tagged for filtering:
- `db` - all database backups
- `db_sqlite` - SQLite backups
- `db_dodeka` - Dodeka backups
- `env_demo` or `env_production` - environment-specific
- `pre-restore` - automatic backup before restore

List snapshots:

```bash
# All dodeka snapshots
restic -r /mnt/backup/restic --password-file /mnt/backup/.restic-password snapshots --tag db_dodeka

# Only production
restic -r /mnt/backup/restic --password-file /mnt/backup/.restic-password snapshots --tag env_production
```

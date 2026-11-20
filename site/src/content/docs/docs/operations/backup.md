---
title: Back up and restore
description: Back up and restore VulWall's MongoDB database.
---

All application data is in MongoDB, in the volume `vulwall_mongo-data`: assets, scans,
discoveries, findings, reports, settings and the admin account.

The other volumes do not need a backup:

| Volume | Contents |
|--------|----------|
| `vulwall_redis-data` | Work in progress of running scans |
| `vulwall_nuclei-templates`, `vulwall_geo-data` | Downloaded again when they are missing |
| `vulwall_web-keys` | Keys that sign login cookies. If you lose them, you only have to log in again. |

## Back up

If you installed with the [install script](/docs/getting-started/install/):

```sh
~/vulwall/vulwall backup
```

This writes two files to the current directory: `vulwall-backup-<time>.archive.gz` with the
database, and `vulwall-backup-<time>.env` with a copy of your settings. Only your user can read
them. To choose the name, add it: `vulwall backup /backups/vulwall.archive.gz`.

Without the `vulwall` command, run this from the install directory (`~/vulwall` by default), and
copy `.env` yourself:

```sh
docker compose exec -T mongo mongodump --db vulwall --archive --gzip > vulwall-$(date +%F).archive.gz
```

Keep the files somewhere other than the VulWall host. They contain your findings and, in `.env`,
your setup token and API keys, so treat them as sensitive.

## Restore

This replaces the current data:

```sh
~/vulwall/vulwall restore vulwall-backup-20260131-020000.archive.gz
```

It asks before it starts. Or, from the install directory:

```sh
docker compose exec -T mongo mongorestore --drop --archive --gzip < vulwall-2026-01-31.archive.gz
```

The restore does not change `.env`. If you restore on a new host, copy the settings you need from
the backup's `.env` file as well.

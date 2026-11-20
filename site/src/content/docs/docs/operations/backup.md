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

Run the commands below from the install directory (`~/vulwall` by default).

## Back up

```sh
docker compose exec -T mongo mongodump --db vulwall --archive --gzip > vulwall-$(date +%F).archive.gz
```

Keep the file somewhere other than the VulWall host. It contains your findings, so treat it as
sensitive.

## Restore

This replaces the current data:

```sh
docker compose exec -T mongo mongorestore --drop --archive --gzip < vulwall-2026-01-31.archive.gz
```

Then restart the stack so the scanner and the web app reload their state:

```sh
docker compose restart
```
